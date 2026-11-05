//! Security descriptors as SDDL text.

use crate::sid;
use std::collections::BTreeSet;

/// A parsed security descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sd {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl_protected: bool,
    pub aces: Vec<Ace>,
}

/// One access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub allow: bool,
    pub flags: AceFlags,
    pub mask: u32,
    pub sid: String,
}

/// The inheritance flags of an [`Ace`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AceFlags {
    pub object_inherit: bool,
    pub container_inherit: bool,
    pub inherit_only: bool,
    pub inherited: bool,
}

/// `APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES`, alias `AC`.
pub const ALL_APP_PACKAGES: &str = "S-1-15-2-1";

/// Every SID alias [`parse`] reads, with its SID. A Windows CI test checks each
/// against Windows' own reading (`sid_aliases_match_windows`).
pub const SID_ALIASES: &[(&str, &str)] = &[
    ("SY", sid::SYSTEM),
    ("BA", sid::ADMINISTRATORS),
    ("BU", sid::USERS),
    ("AU", sid::AUTHENTICATED_USERS),
    ("WD", "S-1-1-0"),
    ("OW", "S-1-3-4"),
    ("CO", "S-1-3-0"),
    ("CG", "S-1-3-1"),
    ("NU", sid::NETWORK),
    ("IU", "S-1-5-4"),
    ("SU", "S-1-5-6"),
    ("AN", "S-1-5-7"),
    ("ED", "S-1-5-9"),
    ("PS", "S-1-5-10"),
    ("RC", "S-1-5-12"),
    ("LS", "S-1-5-19"),
    ("NS", "S-1-5-20"),
    ("WR", "S-1-5-33"),
    ("AC", ALL_APP_PACKAGES),
    ("BG", "S-1-5-32-546"),
    ("PU", "S-1-5-32-547"),
    ("AO", "S-1-5-32-548"),
    ("SO", "S-1-5-32-549"),
    ("PO", "S-1-5-32-550"),
    ("BO", "S-1-5-32-551"),
    ("RE", "S-1-5-32-552"),
    ("RU", "S-1-5-32-554"),
    ("RD", "S-1-5-32-555"),
    ("NO", "S-1-5-32-556"),
    ("MU", "S-1-5-32-558"),
    ("LU", "S-1-5-32-559"),
    ("IS", "S-1-5-32-568"),
    ("CY", "S-1-5-32-569"),
    ("ER", "S-1-5-32-573"),
    ("HA", "S-1-5-32-578"),
    ("AA", "S-1-5-32-579"),
];

/// The SDDL alias of this machine's built-in Administrator (RID 500), as Windows
/// prints it for that account. Its SID needs the machine's domain SID, which the text
/// does not hold, so [`parse`] keeps the alias as the name of the principal. That
/// account is always in `Administrators`, so [`writers`] reports it as that group.
pub const LOCAL_ADMIN: &str = "LA";

/// Descriptors of the folders above saiife's tree, as a stock `windows-latest` runner
/// printed them through `acl::get_sddl` (CI run 41998930399, `real_folders_parse`).
/// Tests read these, not a memory of what Windows ships.
pub mod stock {
    /// `C:\`.
    pub const DRIVE_ROOT: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\
         G:SYD:AI(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-\
         4239452838-1296943325-355587736-700089176)(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)\
         (A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    /// `C:\ProgramData`.
    pub const PROGRAM_DATA: &str = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\
         (A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)";
    /// `C:\Program Files`.
    pub const PROGRAM_FILES: &str = WINDOWS;
    /// `C:\Windows`, the same text as `C:\Program Files` on the runner.
    pub const WINDOWS: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\
         G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\
         D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
         (A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
         (A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)\
         (A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;AC)\
         (A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)";
}

/// Every rights letter pair [`parse`] reads, with its bits (`ADS_RIGHT_*` for the
/// first nine). They are named after directory-service rights, but Windows prints
/// file rights with the same letters, and on a file the names mislead: read them by
/// bit, as the comments do. A Windows CI test checks each against Windows' reading
/// (`right_letters_match_windows`).
pub const RIGHT_LETTERS: &[(&str, u32)] = &[
    ("CC", 0x0000_0001), // FILE_READ_DATA, FILE_LIST_DIRECTORY
    ("DC", 0x0000_0002), // FILE_WRITE_DATA, FILE_ADD_FILE
    ("LC", 0x0000_0004), // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
    ("SW", 0x0000_0008), // FILE_READ_EA
    ("RP", 0x0000_0010), // FILE_WRITE_EA
    ("WP", 0x0000_0020), // FILE_EXECUTE, FILE_TRAVERSE
    ("DT", 0x0000_0040), // FILE_DELETE_CHILD
    ("LO", 0x0000_0080), // FILE_READ_ATTRIBUTES
    ("CR", 0x0000_0100), // FILE_WRITE_ATTRIBUTES
    ("SD", 0x0001_0000),
    ("RC", 0x0002_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("GA", 0x1000_0000),
    ("GX", 0x2000_0000),
    ("GW", 0x4000_0000),
    ("GR", 0x8000_0000),
    ("FA", 0x001f_01ff),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00a0),
];

/// Every right that lets a holder change a file or its protection.
pub const WRITE_LIKE: u32 = 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Reads `O:`, `G:` and `D:` components, in any order, each at most once.
///
/// `D:` is required: [`Sd`] cannot tell "no DACL" or a NULL DACL (which grant
/// everyone everything) from an empty one (which grants nobody anything), and
/// [`writers`] must not call the first two "no writers". The `AI` and `AR`
/// DACL flags are accepted and not kept. Anything else is an error, never a
/// guess: SACLs, other ACE types and flags, object ACEs, whitespace.
///
/// Refused on purpose, since a refusal fails an install and a misread is a hole:
/// - `S:`: `ffi::acl::get_sddl` never asks for a SACL, so real output has none;
/// - the `SA` and `FA` ACE flags: audit flags, which belong to SACL ACEs;
/// - the `NP` ACE flag: [`AceFlags`] has no field for it, and I know of no default
///   ACL above ours that carries it. It changes only what children inherit, so a
///   folder carrying it is refused, not misjudged;
/// - the `TP` and `CR` ACE flags, and every ACE type but `A` and `D`;
/// - the registry rights `KA`, `KR`, `KW`, `KX` and the label rights `NR`, `NW`,
///   `NX`: not file rights;
/// - domain-relative aliases such as `LG` and `DU`, and integrity labels such
///   as `ME`: their SID is not known from the text alone.
///
/// [`LOCAL_ADMIN`] is the one domain-relative alias read, because real output carries
/// it. It stays `LA` in [`Sd`], where every other principal is a SID.
pub fn parse(s: &str) -> Result<Sd, String> {
    if !s.is_ascii() {
        return Err("SDDL is not ASCII".to_string());
    }
    let mut sd = Sd::default();
    let mut seen_dacl = false;
    let mut rest = s;
    while !rest.is_empty() {
        let (tag, body) = rest
            .split_at_checked(2)
            .ok_or_else(|| format!("unknown SDDL component at {rest:?}"))?;
        let end = component_end(body);
        let value = &body[..end];
        match tag {
            "O:" if sd.owner.is_none() => sd.owner = Some(parse_sid(value)?),
            "G:" if sd.group.is_none() => sd.group = Some(parse_sid(value)?),
            "D:" if !seen_dacl => {
                seen_dacl = true;
                parse_dacl(value, &mut sd)?;
            }
            "O:" | "G:" | "D:" => return Err(format!("repeated SDDL component {tag}")),
            _ => return Err(format!("unknown SDDL component at {rest:?}")),
        }
        rest = &body[end..];
    }
    if !seen_dacl {
        return Err("SDDL has no D: component".to_string());
    }
    Ok(sd)
}

/// Where a component's value ends in `body`: at the tag letter before the next
/// `:` outside any ACE, or at the end.
fn component_end(body: &str) -> usize {
    let mut depth = 0usize;
    for (i, b) in body.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => return i.saturating_sub(1),
            _ => {}
        }
    }
    body.len()
}

/// `s`, an ASCII string, cut into two-letter tokens.
fn pairs(s: &str) -> Result<Vec<&str>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{s:?} is not a list of two-letter codes"));
    }
    Ok((0..s.len()).step_by(2).map(|i| &s[i..i + 2]).collect())
}

fn parse_dacl(value: &str, sd: &mut Sd) -> Result<(), String> {
    let (mut flags, mut aces) = value.split_at(value.find('(').unwrap_or(value.len()));
    while !flags.is_empty() {
        if let Some(after) = flags.strip_prefix('P') {
            sd.dacl_protected = true;
            flags = after;
        } else if let Some(after) = flags.strip_prefix("AI").or(flags.strip_prefix("AR")) {
            flags = after;
        } else {
            return Err(format!("unknown DACL flags {flags:?}"));
        }
    }
    while !aces.is_empty() {
        let inner = aces
            .strip_prefix('(')
            .ok_or_else(|| format!("expected an ACE at {aces:?}"))?;
        let close = inner
            .find(')')
            .ok_or_else(|| format!("unterminated ACE at {aces:?}"))?;
        sd.aces.push(parse_ace(&inner[..close])?);
        aces = &inner[close + 1..];
    }
    Ok(())
}

fn parse_ace(text: &str) -> Result<Ace, String> {
    let fields: Vec<&str> = text.split(';').collect();
    let [kind, flags, rights, "", "", sid] = fields[..] else {
        return Err(format!("ACE {text:?} is not (A|D;flags;rights;;;sid)"));
    };
    let allow = match kind {
        "A" => true,
        "D" => false,
        _ => return Err(format!("unknown ACE type {kind:?}")),
    };
    let mut parsed = AceFlags::default();
    for flag in pairs(flags)? {
        match flag {
            "OI" => parsed.object_inherit = true,
            "CI" => parsed.container_inherit = true,
            "IO" => parsed.inherit_only = true,
            "ID" => parsed.inherited = true,
            _ => return Err(format!("unknown ACE flag {flag:?}")),
        }
    }
    Ok(Ace {
        allow,
        flags: parsed,
        mask: parse_rights(rights)?,
        sid: parse_sid(sid)?,
    })
}

fn parse_rights(text: &str) -> Result<u32, String> {
    if let Some(hex) = text.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("bad hex rights {text:?}"));
        }
        return u32::from_str_radix(hex, 16).map_err(|e| format!("bad hex rights {text:?}: {e}"));
    }
    if text.is_empty() {
        return Err("empty ACE rights".to_string());
    }
    let mut mask = 0;
    for letters in pairs(text)? {
        let (_, bits) = RIGHT_LETTERS
            .iter()
            .find(|(l, _)| *l == letters)
            .ok_or_else(|| format!("unknown ACE right {letters:?}"))?;
        mask |= bits;
    }
    Ok(mask)
}

fn parse_sid(text: &str) -> Result<String, String> {
    if let Some((_, sid)) = SID_ALIASES.iter().find(|(alias, _)| *alias == text) {
        return Ok((*sid).to_string());
    }
    if text == LOCAL_ADMIN || sid::valid_sid(text) {
        return Ok(text.to_string());
    }
    Err(format!("unknown SID or alias {text:?}"))
}

/// Parses a descriptor about to be applied to a file: it must name an owner and
/// have a protected DACL (`D:P`). So no ACL reaches disk that would inherit from
/// its parent, and a NULL DACL never gets as far as the FFI.
pub fn check_settable(s: &str) -> Result<Sd, String> {
    let sd = parse(s)?;
    if sd.owner.is_none() {
        return Err(format!("{s:?} names no owner"));
    }
    if !sd.dacl_protected {
        return Err(format!("{s:?} has no protected DACL"));
    }
    Ok(sd)
}

/// Whether a descriptor may be set on an open file with these `dwFileAttributes` and
/// `nNumberOfLinks`, read from the handle about to be changed. A descriptor belongs to
/// the file, not to a name, so setting one through a hard link rewrites the target's
/// too, and whoever planted the link chose that target. A directory cannot be
/// hard-linked. The count must be 1 exactly: anything else is not a file we understand.
pub fn check_links(attributes: u32, links: u32) -> Result<(), String> {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 || links == 1 {
        return Ok(());
    }
    Err(format!(
        "has {links} hard links, and its descriptor would change for every one of them"
    ))
}

/// Whether `actual`, the path `GetFinalPathNameByHandleW` gives for an open handle, is
/// `expected`, the path that was asked for. A junction anywhere on the way makes them
/// differ, which a check of the last component cannot see.
///
/// The `\\?\` prefix is not compared, and `/` counts as `\`. Letters compare as ASCII,
/// ignoring case: a non-ASCII name in another case is refused, which fails closed, and
/// the install tree has none. So does an 8.3 short name, since Windows answers with the
/// long one: canonicalize a path before setting a descriptor on it.
pub fn same_final_path(expected: &str, actual: &str) -> bool {
    fn plain(p: &str) -> String {
        let p = p.replace('/', r"\");
        let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
        // `C:\` keeps its slash; `C:\a\` loses it.
        match p.strip_suffix('\\') {
            Some(rest) if !rest.ends_with(':') => rest.to_string(),
            _ => p.to_string(),
        }
    }
    plain(expected).eq_ignore_ascii_case(&plain(actual))
}

/// Canonical text: hex rights and full SIDs, or [`LOCAL_ADMIN`] for that account.
/// `D:` is always there, and the
/// `AI` and `AR` flags are not, since [`Sd`] does not keep them. So
/// `parse(render(x)) == x`.
pub fn render(sd: &Sd) -> String {
    let mut out = String::new();
    if let Some(owner) = &sd.owner {
        out.push_str(&format!("O:{owner}"));
    }
    if let Some(group) = &sd.group {
        out.push_str(&format!("G:{group}"));
    }
    out.push_str("D:");
    if sd.dacl_protected {
        out.push('P');
    }
    for ace in &sd.aces {
        let kind = if ace.allow { 'A' } else { 'D' };
        let f = ace.flags;
        let flags = [
            (f.object_inherit, "OI"),
            (f.container_inherit, "CI"),
            (f.inherit_only, "IO"),
            (f.inherited, "ID"),
        ]
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, code)| *code)
        .collect::<String>();
        out.push_str(&format!("({kind};{flags};{:#x};;;{})", ace.mask, ace.sid));
    }
    out
}

/// The SIDs an allow ACE grants any [`WRITE_LIKE`] bit, inherit-only ACEs
/// aside. Deny ACEs are not subtracted: an allow is enough to fail, which errs
/// on the safe side. [`LOCAL_ADMIN`] is reported as `Administrators`, the group it
/// cannot leave.
///
/// This covers DACL ACEs only. The owner holds implicit `WRITE_DAC` unless an
/// `OW` ACE limits it, so callers must check the owner separately.
pub fn writers(sd: &Sd) -> BTreeSet<String> {
    sd.aces
        .iter()
        .filter(|a| a.allow && !a.flags.inherit_only && a.mask & WRITE_LIKE != 0)
        .map(|a| {
            if a.sid == LOCAL_ADMIN {
                sid::ADMINISTRATORS.to_string()
            } else {
                a.sid.clone()
            }
        })
        .collect()
}

/// `CREATOR OWNER`: an inherit-only ACE for it grants nothing on this object.
const CREATOR_OWNER: &str = "S-1-3-0";
/// What holds a read right: `FILE_READ_DATA`, `GENERIC_READ`, `GENERIC_ALL`.
const READ_LIKE: u32 = 0x0000_0001 | 0x8000_0000 | 0x1000_0000;

/// Why `text`, a path's descriptor, is not private to the SID `own`: an owner other than
/// SYSTEM, Administrators, TrustedInstaller or `own`, or another SID that may write (and,
/// with `readers_too`, read). `None` when it is private. Text that cannot be read is a
/// problem, never a pass.
pub fn private_problem(text: &str, own: &str, readers_too: bool) -> Option<String> {
    use crate::sid::{ADMINISTRATORS, SYSTEM, TRUSTED_INSTALLER};
    let sd = match parse(text) {
        Ok(sd) => sd,
        Err(e) => return Some(format!("cannot read its descriptor: {e}")),
    };
    // `LA` is how Windows prints the built-in Administrator, always in Administrators.
    let trusted =
        |sid: &str| [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER, LOCAL_ADMIN, own].contains(&sid);
    match sd.owner.as_deref() {
        Some(o) if trusted(o) => {}
        Some(o) => return Some(format!("owned by {o}")),
        None => return Some("no owner in its descriptor".to_string()),
    }
    let wanted = if readers_too {
        WRITE_LIKE | READ_LIKE
    } else {
        WRITE_LIKE
    };
    sd.aces
        .iter()
        .filter(|a| a.allow && !(a.flags.inherit_only && a.sid == CREATOR_OWNER))
        .find(|a| a.mask & wanted != 0 && !trusted(&a.sid))
        .map(|a| match a.mask & WRITE_LIKE {
            0 => format!("{} may read it", a.sid),
            _ => format!("{} may write it", a.sid),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sid::{ADMINISTRATORS, AUTHENTICATED_USERS, SYSTEM, USERS};

    const ME: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn private_problem_reads_owner_writers_and_readers() {
        let ok = format!("O:{ME}G:{ME}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{ME})");
        assert_eq!(private_problem(&ok, ME, true), None);
        assert_eq!(private_problem(MAIN, ME, false), None);
        // Users hold read and execute here: fine for a dir, not for a secret.
        assert!(private_problem(MAIN, ME, true)
            .unwrap()
            .contains("may read"));
        let foreign_owner = "O:S-1-5-21-1-2-3-1002D:P(A;;FA;;;SY)";
        assert!(private_problem(foreign_owner, ME, false)
            .unwrap()
            .contains("owned by"));
        let writer = format!("O:{ME}D:P(A;;FA;;;{ME})(A;;FA;;;BU)");
        assert!(private_problem(&writer, ME, false)
            .unwrap()
            .contains("may write"));
        assert!(private_problem("nonsense", ME, false).is_some());
        assert!(private_problem("D:P(A;;FA;;;SY)", ME, false).is_some());
        // The inherit-only template for new objects grants nothing here.
        let template = format!("O:{ME}D:P(A;;FA;;;{ME})(A;OICIIO;FA;;;CO)");
        assert_eq!(private_problem(&template, ME, true), None);
    }

    const MAIN: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    fn sole_ace(s: &str) -> Ace {
        let sd = parse(s).unwrap();
        assert_eq!(sd.aces.len(), 1, "{s}");
        sd.aces.into_iter().next().unwrap()
    }

    #[test]
    fn sddl_parses_the_main_fixture() {
        let sd = parse(MAIN).unwrap();
        assert_eq!(sd.owner.as_deref(), Some(ADMINISTRATORS));
        assert_eq!(sd.group.as_deref(), Some(SYSTEM));
        assert!(sd.dacl_protected);
        assert_eq!(sd.aces.len(), 3);
        assert!(sd.aces.iter().all(|a| a.allow));
        assert_eq!(sd.aces[0].mask, 0x1f_01ff);
        assert_eq!(sd.aces[2].mask, 0x12_00a9);
        assert_eq!(sd.aces[2].sid, USERS);
        assert!(sd.aces[0].flags.object_inherit && sd.aces[0].flags.container_inherit);
        assert!(!sd.aces[0].flags.inherit_only && !sd.aces[0].flags.inherited);
    }

    #[test]
    fn sddl_renders_canonical_text() {
        assert_eq!(
            render(&parse(MAIN).unwrap()),
            "O:S-1-5-32-544G:S-1-5-18D:P(A;OICI;0x1f01ff;;;S-1-5-18)\
             (A;OICI;0x1f01ff;;;S-1-5-32-544)(A;OICI;0x1200a9;;;S-1-5-32-545)"
        );
    }

    #[test]
    fn sddl_roundtrip() {
        for s in [
            MAIN,
            "D:",
            "D:P",
            "O:S-1-5-21-1-2-3-1001D:AI(A;ID;FR;;;AU)(D;;GWWD;;;WD)",
            "G:BUD:AR(A;CIIO;GA;;;CO)(A;OI;0x0;;;OW)(D;OICIIOID;0xffffffff;;;AN)",
            "D:PAI(A;;FX;;;NU)(A;;FW;;;IU)(A;;RCSDWDWO;;;S-1-5-80-1-2-3-4-5)",
        ] {
            let sd = parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            let text = render(&sd);
            assert_eq!(parse(&text).unwrap(), sd, "{s} -> {text}");
            assert_eq!(render(&parse(&text).unwrap()), text, "{s}");
        }
    }

    #[test]
    fn sddl_component_order_does_not_matter() {
        assert_eq!(
            parse("D:(A;;FA;;;SY)G:BUO:BA").unwrap(),
            parse("O:BAG:BUD:(A;;FA;;;SY)").unwrap()
        );
    }

    #[test]
    fn sddl_aliases_expand() {
        for (alias, sid) in [
            ("SY", SYSTEM),
            ("BA", ADMINISTRATORS),
            ("BU", USERS),
            ("AU", AUTHENTICATED_USERS),
            ("WD", "S-1-1-0"),
            ("OW", "S-1-3-4"),
            ("CO", "S-1-3-0"),
            ("NU", "S-1-5-2"),
            ("IU", "S-1-5-4"),
            ("AN", "S-1-5-7"),
        ] {
            assert_eq!(sole_ace(&format!("D:(A;;FA;;;{alias})")).sid, sid);
            let sd = parse(&format!("O:{alias}G:{alias}D:")).unwrap();
            assert_eq!(sd.owner.as_deref(), Some(sid));
            assert_eq!(sd.group.as_deref(), Some(sid));
        }
    }

    #[test]
    fn sddl_alias_table_expands_and_is_complete() {
        for (alias, sid) in SID_ALIASES {
            assert_eq!(sole_ace(&format!("D:(A;;FA;;;{alias})")).sid, *sid);
            assert!(crate::sid::valid_sid(sid), "{sid}");
        }
        assert_eq!(sole_ace("D:(A;;FA;;;AC)").sid, "S-1-15-2-1");
        assert_eq!(sole_ace("D:(A;;FA;;;SU)").sid, "S-1-5-6");
    }

    /// Microsoft's ACE Strings page: this text is mask 0x100e003f.
    #[test]
    fn rights_match_the_documented_example() {
        assert_eq!(
            sole_ace("D:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)").mask,
            0x100e_003f
        );
    }

    /// The directory-service letters, on a file. A misread here under-reports
    /// writers: `RP` writes EAs, `CR` writes attributes, `DT` deletes children,
    /// `DC` and `LC` add entries. `WP`, `SW`, `CC` and `LO` only read or traverse,
    /// whatever their names say.
    #[test]
    fn letters_mean_their_file_bits() {
        for (letters, mask, writes) in [
            ("CC", 0x1, false),
            ("DC", 0x2, true),
            ("LC", 0x4, true),
            ("SW", 0x8, false),
            ("RP", 0x10, true),
            ("WP", 0x20, false),
            ("DT", 0x40, true),
            ("LO", 0x80, false),
            ("CR", 0x100, true),
        ] {
            let sd = parse(&format!("D:(A;;{letters};;;BU)")).unwrap();
            assert_eq!(sd.aces[0].mask, mask, "{letters}");
            assert_eq!(writers(&sd).contains(USERS), writes, "{letters}");
        }
        // C:\ProgramData's grant to Users, as Windows prints it.
        assert_eq!(sole_ace("D:(A;CI;DCLCRPCR;;;BU)").mask, 0x116);
    }

    /// The real folders, whose owner and grants these tests read as Windows prints them.
    #[test]
    fn stock_descriptors_parse() {
        let ti = crate::sid::TRUSTED_INSTALLER;
        for (s, owner) in [
            (stock::DRIVE_ROOT, ti),
            (stock::PROGRAM_DATA, SYSTEM),
            (stock::PROGRAM_FILES, ti),
            (stock::WINDOWS, ti),
        ] {
            let sd = parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(sd.owner.as_deref(), Some(owner), "{s}");
        }
    }

    #[test]
    fn check_settable_needs_an_owner_and_protection() {
        check_settable("O:BAD:P(A;;FA;;;SY)").unwrap();
        check_settable("O:BAG:SYD:PAI(A;OICI;FA;;;SY)").unwrap();
        check_settable("O:BAD:P").unwrap();
        for s in [
            "D:P(A;;FA;;;SY)",
            "O:BAD:(A;;FA;;;SY)",
            "O:BAD:AI(A;;FA;;;SY)",
            "O:BA",
            "O:BAD:NO_ACCESS_CONTROL",
            "",
        ] {
            assert!(check_settable(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn sddl_rights_letters() {
        for (letters, mask) in [
            ("GA", 0x1000_0000),
            ("GR", 0x8000_0000),
            ("GW", 0x4000_0000),
            ("GX", 0x2000_0000),
            ("FA", 0x1f_01ff),
            ("FR", 0x12_0089),
            ("FW", 0x12_0116),
            ("FX", 0x12_00a0),
            ("RC", 0x2_0000),
            ("SD", 0x1_0000),
            ("WD", 0x4_0000),
            ("WO", 0x8_0000),
            ("GRGW", 0xc000_0000),
        ] {
            assert_eq!(
                sole_ace(&format!("D:(A;;{letters};;;SY)")).mask,
                mask,
                "{letters}"
            );
        }
    }

    #[test]
    fn sddl_ace_flags() {
        let f = sole_ace("D:(A;OICIIOID;FA;;;SY)").flags;
        assert!(f.object_inherit && f.container_inherit && f.inherit_only && f.inherited);
        assert_eq!(sole_ace("D:(A;;FA;;;SY)").flags, AceFlags::default());
        assert!(!sole_ace("D:(D;;FA;;;SY)").allow);
    }

    #[test]
    fn sddl_unknown_alias_is_error() {
        assert!(parse("D:(A;;FA;;;ZZ)").is_err());
        assert!(parse("O:ZZD:").is_err());
        assert!(parse("G:ZZD:").is_err());
    }

    #[test]
    fn sddl_refuses_what_it_does_not_know() {
        for s in [
            // No DACL at all, or a NULL DACL: `Sd` cannot say so, and an empty
            // ACE list would read as "no writers".
            "",
            "O:BA",
            "O:BAG:SY",
            "D:NO_ACCESS_CONTROL",
            // Components.
            "S:(AU;;FA;;;WD)",
            "D:S:",
            "O:BAO:SYD:",
            "G:BAG:SYD:",
            "D:D:",
            " D:",
            "D: ",
            "D:(A;;FA;;;SY) ",
            "O::D:",
            "X:",
            ":",
            "é:",
            "O:éD:",
            // DACL flags.
            "D:Q",
            "D:PQ",
            "D:A",
            "D:p",
            // ACE shape.
            "D:(",
            "D:)",
            "D:()",
            "D:(A;;FA;;;SY",
            "D:(A;;FA;;SY)",
            "D:(A;;FA;;;SY;)",
            "D:(A;;FA;;;SY)x",
            "D:x(A;;FA;;;SY)",
            "D:(A;;FA;;;(SY))",
            // ACE type, flags, GUIDs.
            "D:(OA;;FA;;;SY)",
            "D:(AU;;FA;;;SY)",
            "D:(a;;FA;;;SY)",
            "D:(XA;;FA;;;SY)",
            "D:(A;NP;FA;;;SY)",
            "D:(A;SA;FA;;;SY)",
            "D:(A;FA;FA;;;SY)",
            "D:(A;TP;FA;;;SY)",
            "D:(A;CR;FA;;;SY)",
            "D:(A;O;FA;;;SY)",
            "D:(A;oi;FA;;;SY)",
            "D:(A;;FA;ab;;SY)",
            "D:(A;;FA;;ab;SY)",
            // Rights.
            "D:(A;;;;;SY)",
            "D:(A;;F;;;SY)",
            "D:(A;;ZZ;;;SY)",
            "D:(A;;fa;;;SY)",
            "D:(A;;0x;;;SY)",
            "D:(A;;0xg;;;SY)",
            "D:(A;;0x+1;;;SY)",
            "D:(A;;0x100000000;;;SY)",
            "D:(A;;123;;;SY)",
            "D:(A;;KA;;;SY)",
            "D:(A;;KR;;;SY)",
            "D:(A;;NW;;;SY)",
            // SIDs.
            "D:(A;;FA;;;)",
            "D:(A;;FA;;;sy)",
            "D:(A;;FA;;;LG)",
            "D:(A;;FA;;;DU)",
            "D:(A;;FA;;;ME)",
            "D:(A;;FA;;;S-1-5)",
            "D:(A;;FA;;;S-1-5-018)",
            "D:(A;;FA;;;S:1)",
        ] {
            assert!(parse(s).is_err(), "{s:?} parsed as {:?}", parse(s));
        }
    }

    /// Windows prints the machine's built-in Administrator (RID 500) as `LA`, and the
    /// SID behind it needs the machine's domain SID. So it stays a name.
    #[test]
    fn la_stays_a_name_and_counts_as_admin() {
        let sd = parse("O:LAG:LAD:PAI(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)").unwrap();
        assert_eq!(sd.owner.as_deref(), Some(LOCAL_ADMIN));
        assert_eq!(sd.group.as_deref(), Some(LOCAL_ADMIN));
        assert_eq!(sd.aces[0].sid, LOCAL_ADMIN);
        assert_eq!(parse(&render(&sd)).unwrap(), sd);
        assert_eq!(
            writers(&sd),
            BTreeSet::from([ADMINISTRATORS.to_string(), SYSTEM.to_string()])
        );
        // A read grant to it writes nothing.
        assert!(writers(&parse("D:(A;;0x1200a9;;;LA)").unwrap()).is_empty());
    }

    /// The other domain-relative aliases stay refused, the Guest account first.
    #[test]
    fn la_opens_no_other_domain_relative_alias() {
        for alias in ["LG", "DA", "DU", "DG", "DC", "la", "La", "LAX"] {
            assert!(parse(&format!("O:{alias}D:")).is_err(), "{alias}");
            assert!(parse(&format!("D:(A;;FA;;;{alias})")).is_err(), "{alias}");
        }
    }

    /// A descriptor set through one name of a hard-linked file changes all of them, and
    /// the other name may be a file the setter must not touch.
    #[test]
    fn final_path_compare() {
        let want = r"C:\ProgramData\saiife\etc";
        for same in [
            r"\\?\C:\ProgramData\saiife\etc",
            r"\\?\c:\programdata\SAIIFE\etc",
            r"C:/ProgramData/saiife/etc",
            r"C:\ProgramData\saiife\etc\",
        ] {
            assert!(same_final_path(want, same), "{same}");
        }
        assert!(same_final_path(r"\\?\D:\a\_temp\x", r"\\?\D:\a\_temp\x"));
        assert!(same_final_path(r"C:\", r"\\?\C:\"));
        for other in [
            // A junction took it elsewhere.
            r"\\?\C:\Users\agent\planted\etc",
            r"\\?\C:\Windows\System32\config",
            r"\\?\D:\ProgramData\saiife\etc",
            r"\\?\C:\ProgramData\saiife\etc2",
            r"\\?\C:\ProgramData\saiife",
            r"\\?\UNC\server\share\ProgramData\saiife\etc",
            r"\\?\C:\PROGRA~1\saiife\etc",
            "",
        ] {
            assert!(!same_final_path(want, other), "{other}");
        }
        assert!(!same_final_path(r"C:\", r"\\?\C:"));
    }

    #[test]
    fn check_links_refuses_a_hard_linked_file() {
        const DIRECTORY: u32 = 0x10;
        const ARCHIVE: u32 = 0x20;
        check_links(ARCHIVE, 1).unwrap();
        for links in [0, 2, 3, u32::MAX] {
            let e = check_links(ARCHIVE, links).unwrap_err();
            assert!(e.contains("hard link"), "{e}");
        }
        // A directory has no hard links to refuse, whatever the count says.
        for links in [0, 1, 2] {
            check_links(DIRECTORY, links).unwrap();
            check_links(DIRECTORY | ARCHIVE, links).unwrap();
        }
    }

    #[test]
    fn write_like_is_the_listed_union() {
        assert_eq!(WRITE_LIKE, 0x500d_0156);
        // The read and execute forms hold none of it.
        for letters in ["FR", "FX", "0x1200a9", "RC", "GR", "GX"] {
            let ace = sole_ace(&format!("D:(A;;{letters};;;SY)"));
            assert_eq!(ace.mask & WRITE_LIKE, 0, "{letters}");
        }
    }

    /// Windows prints the built-in Administrator (RID 500) as `LA`, whoever asks. It's a
    /// member of Administrators, so it may own and read what they may; and when that account
    /// runs saiife, its own files print this way too, under its own SID.
    #[test]
    fn private_problem_reads_the_alias_of_the_builtin_admin() {
        let text = "O:LAG:LAD:PAI(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)";
        assert_eq!(private_problem(text, ME, true), None);
        assert_eq!(private_problem(text, "", false), None);
        // The alias is no way in for anyone else.
        let loose = "O:LAG:LAD:PAI(A;;FA;;;LA)(A;;FA;;;S-1-5-21-9-9-9-9)";
        assert!(private_problem(loose, ME, false).is_some());
    }

    #[test]
    fn writers_finds_append_only_grant() {
        let sd = parse("D:(A;;0x4;;;BU)").unwrap();
        assert_eq!(writers(&sd), BTreeSet::from([USERS.to_string()]));
    }

    #[test]
    fn writers_finds_each_write_like_bit() {
        for bit in [
            0x2u32,
            0x4,
            0x10,
            0x40,
            0x100,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let sd = parse(&format!("D:(A;;{bit:#x};;;BU)")).unwrap();
            assert!(writers(&sd).contains(USERS), "{bit:#x}");
        }
    }

    #[test]
    fn writers_ignores_inherit_only() {
        assert!(writers(&parse("D:(A;OICIIO;FA;;;BU)").unwrap()).is_empty());
        // Inheritable but also effective here.
        assert!(!writers(&parse("D:(A;OICI;FA;;;BU)").unwrap()).is_empty());
    }

    #[test]
    fn writers_ignores_readers_and_deny_aces() {
        let sd = parse("D:(A;;0x1200a9;;;BU)(D;;FA;;;AU)").unwrap();
        assert!(writers(&sd).is_empty());
    }

    #[test]
    fn writers_does_not_subtract_a_deny() {
        let sd = parse("D:(D;;FA;;;BU)(A;;FA;;;BU)").unwrap();
        assert_eq!(writers(&sd), BTreeSet::from([USERS.to_string()]));
    }
}
