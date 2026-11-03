//! Windows SIDs as text: well-known values, service SIDs, the uid mapping.

use sha1::Sha1;
use sha2::{Digest, Sha256};

/// `NT AUTHORITY\SYSTEM`.
pub const SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `BUILTIN\Users`.
pub const USERS: &str = "S-1-5-32-545";
/// `NT AUTHORITY\Authenticated Users`.
pub const AUTHENTICATED_USERS: &str = "S-1-5-11";
/// `NT SERVICE\TrustedInstaller`.
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// `NT AUTHORITY\NETWORK`.
pub const NETWORK: &str = "S-1-5-2";

/// The SID Windows derives for a service: `S-1-5-80-` and the five
/// little-endian `u32`s of `SHA-1(UTF-16LE(upper(service_name)))`.
///
/// Windows upcases one UTF-16 unit at a time, so a letter whose upper case is
/// several letters (`ß`) stays as it is.
pub fn service_sid(service_name: &str) -> String {
    let upper: String = service_name
        .chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(one), None) => one,
                _ => c,
            }
        })
        .collect();
    let mut hash = Sha1::new();
    for unit in upper.encode_utf16() {
        hash.update(unit.to_le_bytes());
    }
    let mut sid = String::from("S-1-5-80");
    let digest = hash.finalize();
    let (words, _) = digest.as_chunks::<4>();
    for word in words {
        sid.push_str(&format!("-{}", u32::from_le_bytes(*word)));
    }
    sid
}

/// The uid saiife records for a Windows caller (decision W12, plan 19b).
///
/// 0 for SYSTEM and for an elevated administrator. Anyone else gets a stable
/// value in `0x4000_0000..=0x7fff_ffff`, derived from SHA-256 of the SID: never
/// 0, never `u32::MAX`, and clear of Linux-style ids in mixed fleets' audit
/// views.
///
/// The uid is a display label, and two SIDs can collide. The SID is the
/// identity: never use the uid as a security key.
pub fn uid_of(sid: &str, elevated_admin: bool) -> u32 {
    if sid == SYSTEM || elevated_admin {
        return 0;
    }
    let hash = Sha256::digest(sid.as_bytes());
    0x4000_0000 | (u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) & 0x3fff_ffff)
}

/// Whether `s` is a SID in canonical text: `S-1-<authority>(-<u32>){1,15}`.
///
/// Numbers are plain decimal with no sign or leading zero, since SIDs are
/// compared as text. The authority is below 2^48. Windows writes authorities
/// of 2^32 and up in hex; those are refused, and no well-known SID uses one.
pub fn valid_sid(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let authority = parts.next().unwrap_or("");
    if !canonical_decimal(authority) || !authority.parse::<u64>().is_ok_and(|a| a < 1 << 48) {
        return false;
    }
    let mut subs = 0;
    for part in parts {
        if !canonical_decimal(part) || part.parse::<u32>().is_err() {
            return false;
        }
        subs += 1;
    }
    (1..=15).contains(&subs)
}

fn canonical_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_installer_service_sid() {
        assert_eq!(service_sid("TrustedInstaller"), TRUSTED_INSTALLER);
    }

    /// Two more published service SIDs, so the algorithm is pinned by more
    /// than one vector.
    #[test]
    fn published_service_sids() {
        assert_eq!(
            service_sid("WinDefend"),
            "S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736"
        );
        assert_eq!(
            service_sid("MSSQLSERVER"),
            "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"
        );
    }

    /// Computed independently with Python's hashlib.
    #[test]
    fn saiifed_service_sid() {
        assert_eq!(
            service_sid("saiifed"),
            "S-1-5-80-1485410291-497971702-176010752-1662630379-411534723"
        );
    }

    #[test]
    fn service_sid_is_case_insensitive() {
        assert_eq!(service_sid("saiifed"), service_sid("SAIIFED"));
    }

    /// Windows upcases one UTF-16 unit at a time. `ß` has no single upper
    /// case letter, so it stays, where `str::to_uppercase` would give `SS`.
    #[test]
    fn service_sid_upcases_one_to_one() {
        assert_ne!(service_sid("straße"), service_sid("STRASSE"));
        assert_eq!(service_sid("straße"), service_sid("STRAßE"));
    }

    #[test]
    fn uid_of_system_and_elevated_is_0() {
        assert_eq!(uid_of(SYSTEM, false), 0);
        assert_eq!(uid_of(SYSTEM, true), 0);
        assert_eq!(uid_of("S-1-5-21-1-2-3-1001", true), 0);
    }

    /// Computed independently with Python's hashlib.
    #[test]
    fn uid_of_vector() {
        assert_eq!(uid_of("S-1-5-21-1-2-3-1001", false), 0x4169_ebe5);
    }

    #[test]
    fn uid_of_user_in_high_range() {
        // A fixed xorshift: the same 1000 SIDs on every run.
        let mut x: u32 = 0x9e37_79b9;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..1000 {
            let sid = format!("S-1-5-21-{}-{}-{}-{}", next(), next(), next(), next());
            assert!(valid_sid(&sid), "{sid}");
            let uid = uid_of(&sid, false);
            assert!(uid >= 0x4000_0000, "{sid}: {uid:#x}");
            assert_ne!(uid, u32::MAX, "{sid}");
            assert_eq!(uid, uid_of(&sid, false), "{sid}");
        }
    }

    #[test]
    fn valid_sid_accepts_real_sids() {
        for s in [
            SYSTEM,
            ADMINISTRATORS,
            USERS,
            AUTHENTICATED_USERS,
            TRUSTED_INSTALLER,
            NETWORK,
            "S-1-0-0",
            "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14",
            "S-1-281474976710655-1",
            "S-1-5-4294967295",
        ] {
            assert!(valid_sid(s), "{s}");
        }
    }

    #[test]
    fn valid_sid_refuses_everything_else() {
        for s in [
            "",
            "S",
            "S-1",
            "S-1-5",
            "S-1-5-",
            "S-1--18",
            "S-2-5-18",
            "s-1-5-18",
            " S-1-5-18",
            "S-1-5-18 ",
            "S-1-5-+18",
            "S-1-5-018",
            "S-1-05-18",
            "S-1-5-4294967296",
            "S-1-281474976710656-1",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
            "S-1-5-x",
            "BU",
        ] {
            assert!(!valid_sid(s), "{s:?}");
        }
    }
}
