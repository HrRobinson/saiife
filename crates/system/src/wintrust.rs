//! Whether a file on Windows may be believed (plan 19b, Task 10). Anyone may create
//! `C:\ProgramData\saiife` on a machine without an install, so a file there proves
//! nothing by being there: it counts only when its descriptor and the descriptor of
//! every folder above it say that no non-admin could have put it there.
//!
//! The rules are [`crate::winacl`]'s table and checks. They read SDDL text only, through
//! `sddl_of`, so Linux tests run all of this.
//!
//! This asks who can write, not whether the descriptor is exactly the row's: an admin
//! who edits `config.toml` leaves it with inherited entries, which is safe, and doctor
//! is what reports a descriptor that drifted.

use crate::layout::{Layout, OPT_DIR, WIN_SERVICE};
use crate::winacl::{ancestor_ok, expected, protected_ok, service_may_write};
use saiife_win::sddl::{parse, Sd};
use saiife_win::sid::{service_sid, ADMINISTRATORS};
use std::io;
use std::path::{Path, PathBuf};

/// A placeholder for [`expected`]'s audit group. The files read through this module sit
/// on rows that do not name that group, so no lookup is made on the hook path.
const NO_AUDIT_GROUP: &str = "S-1-0-0";

/// What a system file's descriptors say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// It does not exist.
    Absent,
    /// Only the machine's admins (and the service, where the table says so) could have
    /// written it.
    Trusted,
    /// The folders above it are not ours and the machine has no service `saiifed`, so this
    /// is no install: someone may have planted the file. It says nothing, and must neither
    /// switch a mode nor silence a hook.
    NotOurs(String),
    /// This is an install, and it has gone wrong: the folders above are ours and this file
    /// is open to someone else or cannot be read, or the service exists and a folder has
    /// drifted. A locked host stays locked: this is an error, never a fallback.
    Damaged(String),
}

/// The SID the debug-build test seam `SAIIFE_TEST_TRUST_SID` names. The test suites run
/// as the runner in temp dirs that the runner owns. Release builds have no such seam.
pub fn test_trust_sid() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        std::env::var("SAIIFE_TEST_TRUST_SID").ok()
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// `text` parsed, with `trust_sid` read as `Administrators` wherever it appears.
fn read_sd(text: &str, trust_sid: Option<&str>) -> Result<Sd, String> {
    let mut sd = parse(text)?;
    if let Some(sid) = trust_sid {
        if sd.owner.as_deref() == Some(sid) {
            sd.owner = Some(ADMINISTRATORS.to_string());
        }
        for ace in sd.aces.iter_mut().filter(|a| a.sid == sid) {
            ace.sid = ADMINISTRATORS.to_string();
        }
    }
    Ok(sd)
}

/// [`protected_ok`] for `path` on its row of the table, or with no extra writers on a
/// path the table does not cover (a `--system-config` elsewhere).
fn path_ok(layout: &Layout, path: &Path, sd: &Sd) -> Result<(), String> {
    let service = service_sid(WIN_SERVICE);
    let row = expected(layout, path, NO_AUDIT_GROUP)?;
    if row.as_deref().is_some_and(service_may_write) {
        protected_ok(sd, &[service.as_str()])
    } else {
        protected_ok(sd, &[])
    }
}

/// The folders above `path`, nearest first: below the root of a test layout, and all the
/// way up on the real machine.
fn folders_above<'a>(layout: &Layout, path: &'a Path) -> Vec<&'a Path> {
    let under = !layout.is_system() && path.starts_with(layout.root());
    path.ancestors()
        .skip(1)
        .take_while(|p| !p.as_os_str().is_empty() && !(under && *p == layout.root()))
        .collect()
}

/// The first folder above `path` that is not ours, as a reason. A folder on a row of the
/// table must be protected. Any other must pass [`ancestor_ok`], which lets Users create
/// entries but not replace them, as a stock `C:\ProgramData` does.
fn folders_problem(
    layout: &Layout,
    path: &Path,
    sddl_of: &dyn Fn(&Path) -> io::Result<String>,
    trust_sid: Option<&str>,
) -> Option<String> {
    for folder in folders_above(layout, path) {
        let shown = folder.display();
        let text = match sddl_of(folder) {
            Ok(t) => t,
            Err(e) => return Some(format!("{shown}: {e}")),
        };
        let sd = match read_sd(&text, trust_sid) {
            Ok(sd) => sd,
            Err(e) => return Some(format!("{shown}: {e}")),
        };
        let covered = matches!(expected(layout, folder, NO_AUDIT_GROUP), Ok(Some(_)));
        let verdict = if covered {
            path_ok(layout, folder, &sd)
        } else {
            ancestor_ok(&sd)
        };
        if let Err(e) = verdict {
            return Some(format!("{shown}: {e}"));
        }
    }
    None
}

/// What the descriptors of `path` and of the folders above it say. `sddl_of` refuses a
/// reparse point, so none can be anywhere in the chain of a file that is trusted.
///
/// A missing file costs one failed call: only a file that exists has its folders read.
/// `service_registered` says whether the machine has the service; only an admin can make
/// that true, so a planted tree cannot.
pub fn system_file(
    layout: &Layout,
    path: &Path,
    sddl_of: &dyn Fn(&Path) -> io::Result<String>,
    trust_sid: Option<&str>,
    service_registered: &dyn Fn() -> bool,
) -> Trust {
    let text = match sddl_of(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Trust::Absent,
        Err(e) => Err(e.to_string()),
    };
    if let Some(why) = folders_problem(layout, path, sddl_of, trust_sid) {
        // Only the install's own tree can be drifted: elsewhere the service proves nothing,
        // and it is read only here, off the path of a file that passes.
        if path.starts_with(layout.at(OPT_DIR)) && service_registered() {
            return Trust::Damaged(why);
        }
        return Trust::NotOurs(why);
    }
    let verdict = text
        .and_then(|t| read_sd(&t, trust_sid))
        .and_then(|sd| path_ok(layout, path, &sd));
    match verdict {
        Ok(()) => Trust::Trusted,
        Err(e) => Trust::Damaged(e),
    }
}

/// W19: `exe` and the folder that holds it must pass [`protected_ok`] with no writer beyond
/// SYSTEM, Administrators and TrustedInstaller, and every folder above that [`ancestor_ok`]. `sddl_of` refuses a
/// reparse point, so none can be anywhere in the chain. Runs where Linux runs
/// `root_owned_chain`, and with no exception for any row of the table: the service may
/// not write what it hands a secret to.
pub fn exe_chain(
    exe: &Path,
    sddl_of: &dyn Fn(&Path) -> io::Result<String>,
    trust_sid: Option<&str>,
) -> Result<(), String> {
    let shown = |p: &Path, e: &dyn std::fmt::Display| format!("{}: {e}", p.display());
    let text = sddl_of(exe).map_err(|e| shown(exe, &e))?;
    let sd = read_sd(&text, trust_sid).map_err(|e| shown(exe, &e))?;
    protected_ok(&sd, &[]).map_err(|e| shown(exe, &e))?;
    let folders = exe
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty());
    for (i, folder) in folders.enumerate() {
        let text = sddl_of(folder).map_err(|e| shown(folder, &e))?;
        let sd = read_sd(&text, trust_sid).map_err(|e| shown(folder, &e))?;
        // The folder that holds the exe is where a DLL beside it would land, so it must let
        // no one add an entry. A folder above may, as a stock `C:\ProgramData` does.
        let verdict = if i == 0 {
            protected_ok(&sd, &[])
        } else {
            ancestor_ok(&sd)
        };
        verdict.map_err(|e| shown(folder, &e))?;
    }
    Ok(())
}

/// The service's key below HKLM, and a value every service has.
pub const REG_SERVICE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\saiifed";
pub const REG_SERVICE_VALUE: &str = "ImagePath";

/// Whether the machine has the service `saiifed`. Only an admin can register one, so this
/// tells an install whose folders drifted from a tree someone planted. Any failure other
/// than "not found" reads as registered, the side that stays locked.
pub fn service_registered(host: &dyn crate::host::Host) -> bool {
    !matches!(
        host.reg_value_present(REG_SERVICE_KEY, REG_SERVICE_VALUE),
        Ok(false)
    )
}

/// `path` as a policy names it: `canonicalize` on Windows answers `\\?\C:\Tools\aws.exe`,
/// and `run_allow` says `C:\Tools\aws.exe`. A verbatim UNC path (`\\?\UNC\…`) stays as it
/// is, so it matches no entry.
pub fn plain_path(path: &Path) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{Platform, CONFIG, ETC_DIR, INSTALLED};
    use crate::winacl::expected;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const ME: &str = "S-1-5-21-1-2-3-1001";
    /// A stock `C:\ProgramData` or `C:\`: Users may add entries, nothing more.
    const STOCK: &str = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    /// The tree below a test root, with each path's descriptor.
    struct Tree {
        _dir: tempfile::TempDir,
        layout: Layout,
        sddl: BTreeMap<PathBuf, String>,
        /// Whether the machine has the service.
        service: fn() -> bool,
    }

    impl Tree {
        /// A real install: every path on its row of the table.
        fn installed() -> Tree {
            let dir = tempfile::tempdir().unwrap();
            let layout = Layout::under_for(dir.path(), Platform::Windows);
            let mut sddl = BTreeMap::new();
            for p in [OPT_DIR, ETC_DIR, CONFIG, INSTALLED] {
                let at = layout.at(p);
                let row = expected(&layout, &at, "S-1-5-32-545").unwrap().unwrap();
                sddl.insert(at, row);
            }
            let top = layout.at(OPT_DIR);
            let mut up = top.parent();
            while let Some(p) = up.filter(|p| p.starts_with(layout.root()) && *p != layout.root()) {
                sddl.insert(p.to_path_buf(), STOCK.to_string());
                up = p.parent();
            }
            Tree {
                _dir: dir,
                layout,
                sddl,
                service: || false,
            }
        }

        fn check(&self, what: &str) -> Trust {
            let lookup = |p: &Path| {
                self.sddl
                    .get(p)
                    .cloned()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
            };
            system_file(
                &self.layout,
                &self.layout.at(what),
                &lookup,
                None,
                &self.service,
            )
        }
    }

    #[test]
    fn an_installed_file_is_trusted() {
        let t = Tree::installed();
        assert_eq!(t.check(CONFIG), Trust::Trusted);
        assert_eq!(t.check(INSTALLED), Trust::Trusted);
    }

    /// An admin who edited the config leaves it with inherited entries. That is no
    /// problem; a writer who is not an admin is.
    #[test]
    fn an_edited_file_stays_trusted() {
        let mut t = Tree::installed();
        let edited = "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";
        t.sddl.insert(t.layout.at(CONFIG), edited.into());
        assert_eq!(t.check(CONFIG), Trust::Trusted);
    }

    /// The service exists, so this is an install whose folder drifted (an admin's stray
    /// entry), not somebody's planted tree. Only an admin can register a service.
    #[test]
    fn a_drifted_folder_with_the_service_is_damaged() {
        let mut t = Tree::installed();
        let mine = format!("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{ME})");
        t.sddl.insert(t.layout.at(ETC_DIR), mine);
        assert!(matches!(t.check(CONFIG), Trust::NotOurs(_)));
        t.service = || true;
        match t.check(CONFIG) {
            Trust::Damaged(why) => assert!(why.contains(ME), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    /// The service says something about the install's own tree and nowhere else: a config
    /// the user keeps at `--system-config` below their profile stays not ours.
    #[test]
    fn the_service_vouches_for_no_other_tree() {
        let t = Tree::installed();
        let elsewhere = t.layout.root().join("elsewhere");
        let file = elsewhere.join("config.toml");
        let mine = format!("O:{ME}G:{ME}D:(A;OICI;FA;;;{ME})");
        let lookup = |p: &Path| {
            if p == file || p == elsewhere {
                return Ok(mine.clone());
            }
            Err(io::Error::from(io::ErrorKind::NotFound))
        };
        let got = system_file(&t.layout, &file, &lookup, None, &|| true);
        assert!(matches!(got, Trust::NotOurs(_)), "{got:?}");
    }

    /// Only "the value is not there" says there is no service. A registry that cannot be
    /// read proves nothing, so the hook, status and audit keep to the locked side.
    #[test]
    fn a_failed_service_read_counts_as_registered() {
        use crate::host::{FakeHost, RegValue};
        let dir = tempfile::tempdir().unwrap();
        let host = FakeHost::open(dir.path()).unwrap();
        assert!(!service_registered(&host));
        host.set(|s| {
            s.registry.insert(
                (REG_SERVICE_KEY.to_string(), REG_SERVICE_VALUE.to_string()),
                RegValue::Str(r"C:\ProgramData\saiife\bin\saiife.exe".into()),
            );
        });
        assert!(service_registered(&host));
        host.set(|s| {
            s.registry.clear();
            s.reg_probe_error = Some("Access is denied.".into());
        });
        assert!(service_registered(&host));
    }

    #[test]
    fn a_missing_file_is_absent_and_reads_no_folder() {
        let t = Tree::installed();
        let reads = std::cell::Cell::new(0);
        let lookup = |_: &Path| {
            reads.set(reads.get() + 1);
            Err(io::Error::from(io::ErrorKind::NotFound))
        };
        let got = system_file(&t.layout, &t.layout.at(CONFIG), &lookup, None, &|| false);
        assert_eq!(got, Trust::Absent);
        assert_eq!(reads.get(), 1);
    }

    /// No install, and a user made the folder: whatever the file says, it says nothing.
    #[test]
    fn a_file_in_a_user_owned_tree_is_not_ours() {
        let mut t = Tree::installed();
        let mine = format!("O:{ME}G:{ME}D:(A;OICI;FA;;;{ME})(A;OICI;FA;;;SY)");
        for p in [OPT_DIR, ETC_DIR, CONFIG] {
            t.sddl.insert(t.layout.at(p), mine.clone());
        }
        assert!(matches!(t.check(CONFIG), Trust::NotOurs(_)));
    }

    /// Hard-linking or moving a protected file into a user's own folder gets it no trust.
    #[test]
    fn a_protected_file_in_a_user_owned_folder_is_not_ours() {
        let mut t = Tree::installed();
        let mine = format!("O:{ME}G:{ME}D:(A;OICI;FA;;;{ME})");
        t.sddl.insert(t.layout.at(ETC_DIR), mine);
        match t.check(CONFIG) {
            Trust::NotOurs(why) => assert!(why.contains(ME), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_junction_above_the_file_is_not_ours() {
        let t = Tree::installed();
        let etc = t.layout.at(ETC_DIR);
        let lookup = |p: &Path| {
            if p == etc {
                return Err(io::Error::other("is a reparse point"));
            }
            t.sddl
                .get(p)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        };
        let got = system_file(&t.layout, &t.layout.at(CONFIG), &lookup, None, &|| false);
        assert!(matches!(got, Trust::NotOurs(_)), "{got:?}");
    }

    /// Our folders, and a file open to the users: this is an install gone wrong.
    #[test]
    fn a_writable_file_in_our_tree_is_damaged() {
        let mut t = Tree::installed();
        let open = "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)";
        t.sddl.insert(t.layout.at(CONFIG), open.into());
        match t.check(CONFIG) {
            Trust::Damaged(why) => assert!(why.contains("S-1-5-32-545"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_user_owned_file_in_our_tree_is_damaged() {
        let mut t = Tree::installed();
        let mine = format!("O:{ME}G:{ME}D:PAI(A;;FA;;;SY)(A;;FA;;;BA)");
        t.sddl.insert(t.layout.at(INSTALLED), mine);
        assert!(matches!(t.check(INSTALLED), Trust::Damaged(_)));
    }

    #[test]
    fn unreadable_descriptors_are_never_trusted() {
        let mut t = Tree::installed();
        t.sddl.insert(t.layout.at(CONFIG), "not sddl".into());
        assert!(matches!(t.check(CONFIG), Trust::Damaged(_)));
        let t = Tree::installed();
        let config = t.layout.at(CONFIG);
        let lookup = |p: &Path| {
            if p == config {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(t.sddl.get(p).cloned().unwrap_or_default())
        };
        assert!(matches!(
            system_file(&t.layout, &config, &lookup, None, &|| false),
            Trust::Damaged(_)
        ));
    }

    /// The debug seam makes one SID an admin, and only that SID.
    #[test]
    fn the_trust_seam_covers_one_sid() {
        let mut t = Tree::installed();
        let mine = format!("O:{ME}G:{ME}D:PAI(A;;FA;;;{ME})(A;;FA;;;SY)");
        t.sddl.insert(t.layout.at(CONFIG), mine);
        let lookup = |p: &Path| {
            t.sddl
                .get(p)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        };
        let at = t.layout.at(CONFIG);
        assert!(matches!(
            system_file(&t.layout, &at, &lookup, None, &|| false),
            Trust::Damaged(_)
        ));
        assert_eq!(
            system_file(&t.layout, &at, &lookup, Some(ME), &|| false),
            Trust::Trusted
        );
        assert!(matches!(
            system_file(&t.layout, &at, &lookup, Some("S-1-5-21-9-9-9-9"), &|| false),
            Trust::Damaged(_)
        ));
    }

    fn chain(sddl: &[(&str, &str)]) -> impl Fn(&Path) -> io::Result<String> {
        let map: BTreeMap<PathBuf, String> = sddl
            .iter()
            .map(|(p, s)| (PathBuf::from(p), s.to_string()))
            .collect();
        move |p: &Path| {
            map.get(p)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    const SAFE_EXE: &str = "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";

    #[test]
    fn exe_chain_takes_an_admin_path() {
        let of = chain(&[
            ("/d/t/aws.exe", SAFE_EXE),
            ("/d/t", STOCK),
            ("/d", STOCK),
            ("/", STOCK),
        ]);
        assert_eq!(exe_chain(Path::new("/d/t/aws.exe"), &of, None), Ok(()));
    }

    #[test]
    fn exe_chain_refuses_a_writer_anywhere() {
        let user_file = format!("O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;{ME})");
        let of = chain(&[("/d/aws.exe", &user_file), ("/d", STOCK), ("/", STOCK)]);
        let e = exe_chain(Path::new("/d/aws.exe"), &of, None).unwrap_err();
        assert!(e.contains(ME), "{e}");

        let user_owned = format!("O:{ME}G:SYD:PAI(A;;FA;;;SY)");
        let of = chain(&[("/d/aws.exe", &user_owned), ("/d", STOCK), ("/", STOCK)]);
        assert!(exe_chain(Path::new("/d/aws.exe"), &of, None).is_err());

        // The folder that holds it must be as closed as the file. A stock `C:\ProgramData`
        // passes as an ancestor, and Users could drop a DLL beside the exe in it.
        let creatable = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x116;;;BU)";
        let of = chain(&[
            ("/d/t/aws.exe", SAFE_EXE),
            ("/d/t", creatable),
            ("/d", STOCK),
            ("/", STOCK),
        ]);
        let e = exe_chain(Path::new("/d/t/aws.exe"), &of, None).unwrap_err();
        assert!(e.starts_with("/d/t:"), "{e}");
        // Above that folder, the same descriptor is what a stock machine has.
        let of = chain(&[
            ("/d/t/aws.exe", SAFE_EXE),
            ("/d/t", STOCK),
            ("/d", creatable),
            ("/", STOCK),
        ]);
        assert_eq!(exe_chain(Path::new("/d/t/aws.exe"), &of, None), Ok(()));

        // A folder a user may replace things in.
        let user_dir = format!("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;;0x10000;;;{ME})");
        let of = chain(&[("/d/aws.exe", SAFE_EXE), ("/d", &user_dir), ("/", STOCK)]);
        assert!(exe_chain(Path::new("/d/aws.exe"), &of, None).is_err());
    }

    /// `sddl_of` refuses a reparse point, on the file or on any folder.
    #[test]
    fn exe_chain_refuses_what_it_cannot_read() {
        let of = chain(&[("/d/aws.exe", SAFE_EXE), ("/", STOCK)]);
        let e = exe_chain(Path::new("/d/aws.exe"), &of, None).unwrap_err();
        assert!(e.starts_with("/d:"), "{e}");
    }

    #[test]
    fn plain_path_strips_only_the_drive_form() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\Tools\aws.exe")),
            Path::new(r"C:\Tools\aws.exe")
        );
        let unc = r"\\?\UNC\srv\share\aws.exe";
        assert_eq!(plain_path(Path::new(unc)), Path::new(unc));
        assert_eq!(plain_path(Path::new("/usr/bin/x")), Path::new("/usr/bin/x"));
    }
}
