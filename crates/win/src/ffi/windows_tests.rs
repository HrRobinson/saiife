//! Run in CI's `test` job on `windows-latest`, with no admin rights assumed. They
//! cannot run anywhere else: no Windows machine builds this crate locally.

use super::{account, acl, sd, token};
use crate::sddl;
use crate::sid::{self, ADMINISTRATORS, USERS};
use std::io::Write;
use std::path::PathBuf;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
};

/// A fresh dir under the runner's temp dir, removed on drop. `RUNNER_TEMP` is CI's
/// own; the system temp dir stands in elsewhere.
fn temp_dir() -> tempfile::TempDir {
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    tempfile::tempdir_in(base).unwrap()
}

/// A descriptor only the runner's user can use: owner and full control.
fn own_sddl(flags: &str, sid: &str) -> String {
    format!("O:{sid}D:{flags}(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
}

/// libtest captures `print!`, also on a pass; this reaches the CI log anyway.
fn log(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

#[test]
fn current_token_has_user_sid() {
    let facts = token::current().unwrap();
    assert!(sid::valid_sid(&facts.sid), "{}", facts.sid);
    assert!(!facts.group_sids.is_empty());
    assert!(
        facts.group_sids.iter().all(|g| sid::valid_sid(g)),
        "{facts:?}"
    );
    assert_eq!(
        facts.elevated_admin,
        facts.group_sids.iter().any(|g| g == ADMINISTRATORS)
    );
}

#[test]
fn facts_of_refuses_a_bad_handle() {
    assert!(token::facts_of(std::ptr::null_mut()).is_err());
}

#[test]
fn lookup_name_of_own_user_roundtrips() {
    let me = token::current().unwrap().sid;
    let name = account::lookup_sid(&me).unwrap();
    let (sid, canonical) = account::lookup_name(&name).unwrap();
    assert_eq!(sid, me);
    assert_eq!(canonical, name);
    assert!(name.contains('\\'), "{name}");
}

#[test]
fn lookup_refuses_what_is_no_account() {
    assert!(account::lookup_name("").is_err());
    assert!(account::lookup_name("no-such-account-saiife-test").is_err());
    assert!(account::lookup_sid("not a sid").is_err());
}

#[test]
fn get_sddl_of_temp_dir_parses() {
    let dir = temp_dir();
    let text = acl::get_sddl(dir.path()).unwrap();
    log(&format!("temp dir SDDL: {text}"));
    let parsed = sddl::parse(&text).unwrap();
    assert!(parsed.owner.is_some(), "{text}");
    assert!(parsed.group.is_some(), "{text}");
}

#[test]
fn get_sddl_of_a_missing_path_is_an_error() {
    let dir = temp_dir();
    assert!(acl::get_sddl(&dir.path().join("missing")).is_err());
}

#[test]
fn set_sddl_on_temp_dir_roundtrips() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let wanted = own_sddl("PAI", &me);
    acl::set_sddl(&target, &wanted).unwrap();

    let read = sddl::parse(&acl::get_sddl(&target).unwrap()).unwrap();
    let want = sddl::parse(&wanted).unwrap();
    assert_eq!(read.owner, want.owner);
    assert!(read.dacl_protected);
    assert_eq!(read.aces, want.aces);
}

#[test]
fn set_sddl_refuses_an_unprotected_or_ownerless_descriptor() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let before = acl::get_sddl(dir.path()).unwrap();
    for bad in [
        format!("O:{me}D:(A;;FA;;;{me})"),
        format!("D:P(A;;FA;;;{me})"),
        format!("O:{me}D:NO_ACCESS_CONTROL"),
    ] {
        assert!(acl::set_sddl(dir.path(), &bad).is_err(), "{bad}");
    }
    assert_eq!(acl::get_sddl(dir.path()).unwrap(), before);
}

#[test]
fn create_dir_with_sddl_has_no_inherited_aces() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("made");
    let wanted = own_sddl("PAI", &me);
    acl::create_dir_with_sddl(&target, &wanted).unwrap();
    let read = sddl::parse(&acl::get_sddl(&target).unwrap()).unwrap();
    assert!(read.dacl_protected);
    assert!(read.aces.iter().all(|a| !a.flags.inherited), "{read:?}");
    assert_eq!(read.aces, sddl::parse(&wanted).unwrap().aces);

    // A second create is an error, and leaves the first alone.
    assert!(acl::create_dir_with_sddl(&target, &wanted).is_err());
}

#[test]
fn reparse_points_are_refused() {
    let dir = temp_dir();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    // Creating a symlink needs a privilege the runner normally holds; without it the
    // refusal cannot be shown here.
    if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
        log("reparse_points_are_refused: no symlink privilege, skipped");
        return;
    }
    let me = token::current().unwrap().sid;
    assert!(acl::get_sddl(&link).is_err());
    assert!(acl::set_sddl(&link, &own_sddl("P", &me)).is_err());
}

#[test]
fn local_groups_of_runner_includes_users() {
    let me = token::current().unwrap().sid;
    let name = account::lookup_sid(&me).unwrap();
    let groups = account::local_groups_of(&name).unwrap();
    log(&format!("local groups of {name}: {groups:?}"));
    // By SID: the names are localized.
    let sids: Vec<String> = groups
        .iter()
        .map(|g| account::lookup_name(g).unwrap().0)
        .collect();
    assert!(sids.iter().any(|s| s == USERS), "{groups:?} {sids:?}");
}

#[test]
fn local_group_members_of_administrators_reads() {
    let (_, name) = account::lookup_name(ADMINISTRATORS_NAME).unwrap_or_else(|_| {
        let name = account::lookup_sid(ADMINISTRATORS).unwrap();
        (ADMINISTRATORS.to_string(), name)
    });
    let bare = name.rsplit('\\').next().unwrap();
    let members = account::local_group_members(bare).unwrap();
    log(&format!("members of {name}: {members:?}"));
    assert!(!members.is_empty());
    assert!(account::local_group_members("no-such-group-saiife-test").is_err());
}

const ADMINISTRATORS_NAME: &str = "Administrators";

/// The real descriptors `ancestor_ok` must read on every machine. Printed first, so a
/// parse failure shows the text it choked on, and the text is on record for the plan's
/// review of [`sddl::parse`].
#[test]
fn real_folders_parse() {
    for path in [
        r"C:\",
        r"C:\Program Files",
        r"C:\ProgramData",
        r"C:\Windows",
    ] {
        let text = acl::get_sddl(std::path::Path::new(path)).unwrap();
        log(&format!("real SDDL of {path}: {text}"));
        sddl::parse(&text).unwrap_or_else(|e| panic!("{path}: {text}: {e}"));
    }
}

/// Every alias [`sddl::parse`] expands, against Windows' own reading of it. A wrong
/// entry in the table would be a misread, so a hole.
#[test]
fn sid_aliases_match_windows() {
    for (alias, want) in sddl::SID_ALIASES {
        let desc = sd::from_sddl(&format!("O:{alias}D:")).unwrap();
        let got = account::sid_to_string(desc.owner_sid().unwrap()).unwrap();
        assert_eq!(got, *want, "{alias}");
    }
}

/// Every rights letter [`sddl::parse`] reads, against Windows' own reading: the letters
/// and our hex for them must be the same descriptor.
#[test]
fn right_letters_match_windows() {
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    for (letters, mask) in sddl::RIGHT_LETTERS {
        let by_letters = sd::from_sddl(&format!("D:(A;;{letters};;;SY)")).unwrap();
        let by_hex = sd::from_sddl(&format!("D:(A;;{mask:#x};;;SY)")).unwrap();
        assert_eq!(
            by_letters.to_sddl(info).unwrap(),
            by_hex.to_sddl(info).unwrap(),
            "{letters}"
        );
    }
}

#[test]
fn from_sddl_gives_the_owner_and_refuses_a_null_dacl() {
    let desc = sd::from_sddl("O:BAD:P(A;;FA;;;SY)").unwrap();
    let owner = account::sid_to_string(desc.owner_sid().unwrap()).unwrap();
    assert_eq!(owner, ADMINISTRATORS);
    desc.dacl().unwrap();

    let null_dacl = sd::from_sddl("O:BAD:NO_ACCESS_CONTROL").unwrap();
    assert!(null_dacl.dacl().is_err());
    let no_owner = sd::from_sddl("D:P(A;;FA;;;SY)").unwrap();
    assert!(no_owner.owner_sid().is_err());
    assert!(sd::from_sddl("not sddl").is_err());
}
