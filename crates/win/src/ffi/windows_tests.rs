//! Run in CI's `test` job on `windows-latest`, with no admin rights assumed. They
//! cannot run anywhere else: no Windows machine builds this crate locally.

use super::{account, acl, sd, token};
use crate::sddl;
use crate::sid::{self, ADMINISTRATORS};
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
    // Canonical: `set_sddl` compares the path it gets with where the handle really is,
    // and the runner's %TEMP% can hold an 8.3 name.
    tempfile::tempdir_in(std::fs::canonicalize(base).unwrap()).unwrap()
}

/// A descriptor only the runner's user can use: owner and full control.
fn own_sddl(flags: &str, sid: &str) -> String {
    format!("O:{sid}D:{flags}(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
}

/// libtest captures `print!`, also on a pass; this reaches the CI log anyway.
fn log(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// The SID behind `LA` on this machine, by Windows' own reading.
fn local_admin_sid() -> String {
    let desc = sd::from_sddl(&format!("O:{}D:", sddl::LOCAL_ADMIN)).unwrap();
    let owner = desc.owner_sid().unwrap();
    // SAFETY: `owner` points into `desc`, alive here.
    unsafe { account::sid_to_string(owner) }.unwrap()
}

/// `text`, with `me` as Windows prints it back: `LA` if it is the built-in Administrator
/// of this machine, which the runner is.
fn as_printed(text: &str, me: &str) -> String {
    if me == local_admin_sid() {
        text.replace(me, sddl::LOCAL_ADMIN)
    } else {
        text.to_string()
    }
}

/// The alias [`sddl::parse`] keeps by name is the account the plan takes it for: RID 500,
/// and in `Administrators`, the claim `writers` and `owner_ok` rest on.
#[test]
fn la_is_the_builtin_administrator_of_this_machine() {
    let la = local_admin_sid();
    assert!(la.starts_with("S-1-5-21-") && la.ends_with("-500"), "{la}");
    let name = account::lookup_sid(&la).unwrap();
    let sids: Vec<String> = account::local_groups_of(&name)
        .unwrap()
        .iter()
        .map(|g| account::lookup_name(g).unwrap().0)
        .collect();
    assert!(sids.iter().any(|s| s == ADMINISTRATORS), "{name}: {sids:?}");
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

/// W1: a junction above the last component is followed on open, and `set_sddl` must see
/// through it. The target keeps its descriptor.
#[test]
fn set_sddl_refuses_a_junction_above_the_path() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let child = real.join("child");
    std::fs::create_dir(&child).unwrap();
    let before = acl::get_sddl(&child).unwrap();
    let link = dir.path().join("link");
    if let Err(e) = std::os::windows::fs::symlink_dir(&real, &link) {
        assert!(
            std::env::var_os("RUNNER_TEMP").is_none(),
            "the CI runner should be able to make a link: {e}"
        );
        return;
    }
    let e = acl::set_sddl(&link.join("child"), &own_sddl("P", &me)).unwrap_err();
    assert!(e.to_string().contains("is really"), "{e}");
    assert_eq!(acl::get_sddl(&child).unwrap(), before);
    // Its true path is fine.
    acl::set_sddl(&child, &own_sddl("P", &me)).unwrap();
}

/// A handle with no `FILE_SHARE_DELETE` stops a rename of the directory, but not a
/// descriptor change or a listing of it.
#[test]
fn hold_dir_stops_a_rename_only() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("held");
    std::fs::create_dir(&target).unwrap();
    let other = dir.path().join("moved");
    let held = acl::hold_dir(&target).unwrap();
    assert!(std::fs::rename(&target, &other).is_err());
    acl::set_sddl(&target, &own_sddl("P", &me)).unwrap();
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    drop(held);
    std::fs::rename(&target, &other).unwrap();
}

/// One holder at a time, and the file goes with the handle.
#[test]
fn lock_file_excludes_and_cleans_up() {
    let dir = temp_dir();
    let path = dir.path().join("install.lock");
    let first = acl::lock_file(&path).unwrap().expect("free");
    assert!(acl::lock_file(&path).unwrap().is_none(), "held");
    drop(first);
    assert!(!path.exists());
    assert!(acl::lock_file(&path).unwrap().is_some());
}

#[test]
fn local_group_lookup_reads_the_kind() {
    assert!(account::lookup_local_group("no-such-account-saiife-test")
        .unwrap()
        .is_none());
    // A user is an account, and no group.
    let me = token::current().unwrap().sid;
    let name = account::lookup_sid(&me).unwrap();
    assert!(account::lookup_local_group(&name).is_err());
    // `Users` is a builtin alias, the same kind as a local group.
    let users = account::lookup_sid("S-1-5-32-545").unwrap();
    assert_eq!(
        account::lookup_local_group(&users).unwrap().as_deref(),
        Some("S-1-5-32-545")
    );
}

#[test]
fn set_sddl_on_temp_dir_roundtrips() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let child = target.join("child");
    std::fs::write(&child, b"x").unwrap();
    let child_before = acl::get_sddl(&child).unwrap();
    // Not the temp dir's own ACEs, so a propagated change would show in the child.
    let wanted = format!("{}(A;OICI;0x1200a9;;;BU)", own_sddl("PAI", &me));
    acl::set_sddl(&target, &wanted).unwrap();

    // Printed first, and in every failure: only a real run can say how Windows spells it.
    let text = acl::get_sddl(&target).unwrap();
    log(&format!("set_sddl roundtrip wrote {wanted}, reads {text}"));
    let child_after = acl::get_sddl(&child).unwrap();
    log(&format!(
        "its existing child read {child_before}, now {child_after}"
    ));
    let read = sddl::parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
    let want = sddl::parse(&as_printed(&wanted, &me)).unwrap();
    assert_eq!(read.owner, want.owner, "{text}");
    assert!(read.dacl_protected, "{text}");
    assert_eq!(read.aces, want.aces, "{text}");

    // CI showed `SetSecurityInfo` on a directory propagating to a child that
    // inherits: the child read back `AI(A;ID;FA;;;LA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)`,
    // its old inherited entries plus the new Users entry, all inherited. `LA` and
    // `S-1-5-32-544` can name the same account, so both sides are normalised.
    let norm = |sid: &str| {
        if sid == sddl::LOCAL_ADMIN {
            local_admin_sid()
        } else {
            sid.to_string()
        }
    };
    let aces_of = |sd: &sddl::Sd| {
        sd.aces
            .iter()
            .map(|a| (a.allow, a.flags, a.mask, norm(&a.sid)))
            .collect::<Vec<_>>()
    };
    let before = sddl::parse(&child_before).unwrap();
    let after = sddl::parse(&child_after).unwrap_or_else(|e| panic!("{child_after}: {e}"));
    let after_aces = aces_of(&after);
    for old in aces_of(&before) {
        assert!(after_aces.contains(&old), "{old:?} lost: {child_after}");
    }
    assert!(
        after.aces.iter().all(|a| a.flags.inherited),
        "{child_after}"
    );
    assert!(
        after
            .aces
            .iter()
            .any(|a| a.allow && a.mask == 0x1200a9 && (a.sid == "BU" || a.sid == "S-1-5-32-545")),
        "the new Users entry did not reach the child: {child_after}"
    );

    // A protected child (`P`) does not receive it; its own entries stay.
    let prot = target.join("prot");
    std::fs::create_dir(&prot).unwrap();
    let prot_text = own_sddl("PAI", &me);
    acl::set_sddl(&prot, &prot_text).unwrap();
    // Set the parent again so propagation runs after the child is protected.
    acl::set_sddl(&target, &wanted).unwrap();
    let prot_after = acl::get_sddl(&prot).unwrap();
    log(&format!("protected child reads {prot_after}"));
    let prot_sd = sddl::parse(&prot_after).unwrap_or_else(|e| panic!("{prot_after}: {e}"));
    assert!(prot_sd.dacl_protected, "{prot_after}");
    assert!(
        prot_sd.aces.iter().all(|a| a.mask != 0x1200a9),
        "the new Users entry reached a protected child: {prot_after}"
    );
    assert_eq!(
        aces_of(&prot_sd),
        aces_of(&sddl::parse(&prot_text).unwrap()),
        "{prot_after}"
    );
}

/// `winacl::actual_ok` compares the group, so a row's `G:SY` must reach disk.
#[test]
fn set_sddl_applies_a_group_and_leaves_it_when_absent() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let group_of = || sddl::parse(&acl::get_sddl(&target).unwrap()).unwrap().group;

    let with_group = format!("O:{me}G:SYD:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
    acl::set_sddl(&target, &with_group).unwrap();
    assert_eq!(group_of().as_deref(), Some(sid::SYSTEM));

    acl::set_sddl(&target, &own_sddl("PAI", &me)).unwrap();
    assert_eq!(group_of().as_deref(), Some(sid::SYSTEM));
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
    assert_eq!(
        read.aces,
        sddl::parse(&as_printed(&wanted, &me)).unwrap().aces
    );

    // A second create is an error, and leaves the first alone.
    assert!(acl::create_dir_with_sddl(&target, &wanted).is_err());
}

#[test]
fn reparse_points_are_refused() {
    let dir = temp_dir();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    // Creating a symlink needs a privilege. The CI runner holds it, so there this test
    // must run; only a local machine without it may skip.
    if let Err(e) = std::os::windows::fs::symlink_dir(&real, &link) {
        assert!(
            std::env::var_os("RUNNER_TEMP").is_none(),
            "the CI runner could not make a symlink: {e}"
        );
        log("reparse_points_are_refused: no symlink privilege, skipped");
        return;
    }
    let me = token::current().unwrap().sid;
    assert!(acl::get_sddl(&link).is_err());
    let before = acl::get_sddl(&real).unwrap();
    let e = acl::set_sddl(&link, &own_sddl("P", &me)).unwrap_err();
    assert!(e.to_string().contains("reparse point"), "{e}");
    assert_eq!(
        acl::get_sddl(&real).unwrap(),
        before,
        "the target must not change"
    );
}

/// A descriptor belongs to the file, so a set through either name would reach both.
#[test]
fn hard_linked_files_are_refused() {
    let me = token::current().unwrap().sid;
    let dir = temp_dir();
    let target = dir.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    let link = dir.path().join("link");
    std::fs::hard_link(&target, &link).unwrap();
    let before = acl::get_sddl(&target).unwrap();
    for name in [&link, &target] {
        let e = acl::set_sddl(name, &own_sddl("P", &me)).unwrap_err();
        assert!(e.to_string().contains("hard link"), "{e}");
        assert_eq!(
            acl::get_sddl(&target).unwrap(),
            before,
            "the target must not change"
        );
    }
    // With the link gone it is a plain file again, and the refusal was the link's.
    std::fs::remove_file(&link).unwrap();
    acl::set_sddl(&target, &own_sddl("P", &me)).unwrap();
    assert_ne!(acl::get_sddl(&target).unwrap(), before);
}

/// Not every account is in `Users`: the runner's built-in Administrator has only
/// `Administrators`. So this reads what the account is in, and nothing in saiife may
/// take `Users` for granted.
#[test]
fn local_groups_of_runner_resolve() {
    let facts = token::current().unwrap();
    let name = account::lookup_sid(&facts.sid).unwrap();
    let groups = account::local_groups_of(&name).unwrap();
    log(&format!("local groups of {name}: {groups:?}"));
    // By SID: the names are localized.
    let sids: Vec<String> = groups
        .iter()
        .map(|g| account::lookup_name(g).unwrap().0)
        .collect();
    assert!(
        sids.iter().all(|s| sid::valid_sid(s)),
        "{groups:?} {sids:?}"
    );
    if facts.elevated_admin {
        assert!(
            sids.iter().any(|s| s == ADMINISTRATORS),
            "{groups:?} {sids:?}"
        );
    }
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
        let owner = desc.owner_sid().unwrap();
        // SAFETY: `owner` points into `desc`, alive here.
        let got = unsafe { account::sid_to_string(owner) }.unwrap();
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
    let owner = desc.owner_sid().unwrap();
    // SAFETY: `owner` points into `desc`, alive here.
    let owner = unsafe { account::sid_to_string(owner) }.unwrap();
    assert_eq!(owner, ADMINISTRATORS);
    desc.dacl().unwrap();

    let null_dacl = sd::from_sddl("O:BAD:NO_ACCESS_CONTROL").unwrap();
    assert!(null_dacl.dacl().is_err());
    let no_owner = sd::from_sddl("D:P(A;;FA;;;SY)").unwrap();
    assert!(no_owner.owner_sid().is_err());
    assert!(sd::from_sddl("not sddl").is_err());
}
