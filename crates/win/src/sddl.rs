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
        mask |= match letters {
            "GA" => 0x1000_0000,
            "GR" => 0x8000_0000,
            "GW" => 0x4000_0000,
            "GX" => 0x2000_0000,
            "FA" => 0x001f_01ff,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00a0,
            "RC" => 0x0002_0000,
            "SD" => 0x0001_0000,
            "WD" => 0x0004_0000,
            "WO" => 0x0008_0000,
            _ => return Err(format!("unknown ACE right {letters:?}")),
        };
    }
    Ok(mask)
}

fn parse_sid(text: &str) -> Result<String, String> {
    let sid = match text {
        "SY" => sid::SYSTEM,
        "BA" => sid::ADMINISTRATORS,
        "BU" => sid::USERS,
        "AU" => sid::AUTHENTICATED_USERS,
        "WD" => "S-1-1-0",
        "OW" => "S-1-3-4",
        "CO" => "S-1-3-0",
        "NU" => sid::NETWORK,
        "IU" => "S-1-5-4",
        "AN" => "S-1-5-7",
        _ if sid::valid_sid(text) => text,
        _ => return Err(format!("unknown SID or alias {text:?}")),
    };
    Ok(sid.to_string())
}

/// Canonical text: hex rights and full SIDs. `D:` is always there, and the
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
/// on the safe side.
pub fn writers(sd: &Sd) -> BTreeSet<String> {
    sd.aces
        .iter()
        .filter(|a| a.allow && !a.flags.inherit_only && a.mask & WRITE_LIKE != 0)
        .map(|a| a.sid.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sid::{ADMINISTRATORS, AUTHENTICATED_USERS, SYSTEM, USERS};

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
            // SIDs.
            "D:(A;;FA;;;)",
            "D:(A;;FA;;;sy)",
            "D:(A;;FA;;;S-1-5)",
            "D:(A;;FA;;;S-1-5-018)",
            "D:(A;;FA;;;S:1)",
        ] {
            assert!(parse(s).is_err(), "{s:?} parsed as {:?}", parse(s));
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
