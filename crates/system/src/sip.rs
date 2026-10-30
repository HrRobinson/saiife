//! System Integrity Protection on macOS (owner ruling on plan 13 A4).
//!
//! The hardened runtime keeps `DYLD_INSERT_LIBRARIES` out of the managed
//! hook only while SIP is on: the locked-macos CI runners (SIP disabled)
//! loaded an injected library into the ad-hoc signed hook. So install
//! refuses and doctor fails on macOS unless `csrutil status` says, exactly,
//! that SIP is enabled. Everything else (disabled, unknown, a custom
//! configuration, an error, any other text) is "not enabled": fail closed.

use crate::host::CmdOutput;

/// `csrutil`, by its absolute path.
pub const CSRUTIL: &str = "/usr/bin/csrutil";

/// The only `csrutil status` output taken as "on".
pub const SIP_ENABLED_LINE: &str = "System Integrity Protection status: enabled.";

/// Why locked mode refuses (install, after `saiife: `) and doctor fails.
pub const SIP_REQUIRED: &str = "locked mode on macOS needs System Integrity Protection: \
     without it the hardened runtime does not stop library injection \
     (DYLD_INSERT_LIBRARIES). Enable SIP (Recovery: csrutil enable) and run install again.";

/// What a test build with [`SIP_SEAM`] adds (install warning, doctor Warn).
pub const SIP_BYPASSED: &str = "(test build: SIP check bypassed)";

/// The CI-only seam: honoured by a build with debug assertions (the
/// ci-locked profile) when set to `1`. A release build has no such name
/// and never reads it ([`seam_set`]).
#[cfg(debug_assertions)]
pub const SIP_SEAM: &str = "SAIIFE_TEST_ALLOW_SIP_OFF";

/// True only for `csrutil status` exiting 0 with exactly
/// [`SIP_ENABLED_LINE`] (trailing whitespace aside). "unknown (Custom
/// Configuration)" and its per-part list are refused even when every part
/// says enabled: only the plain line is plainly fully enabled.
pub fn parse_status(out: &CmdOutput) -> bool {
    out.status == 0 && out.stdout.trim_end() == SIP_ENABLED_LINE
}

/// The seam is set (`SAIIFE_TEST_ALLOW_SIP_OFF=1`) and this build honours
/// it. Always false without debug assertions.
pub fn seam_set() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(SIP_SEAM).is_some_and(|v| v == "1")
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// The SIP verdict for install and doctor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipVerdict {
    /// SIP is on.
    Enabled,
    /// SIP is not on, and the test seam lets this test build go on.
    Bypassed,
    /// SIP is not on: refuse.
    Required,
}

/// `enabled` from [`crate::host::Host::sip_enabled`], `seam` from
/// [`seam_set`] (passed in, so tests never touch the environment).
pub fn verdict(enabled: bool, seam: bool) -> SipVerdict {
    match (enabled, seam) {
        (true, _) => SipVerdict::Enabled,
        (false, true) => SipVerdict::Bypassed,
        (false, false) => SipVerdict::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(status: i32, stdout: &str) -> CmdOutput {
        CmdOutput {
            status,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn only_the_plain_enabled_line_is_on() {
        assert!(parse_status(&out(
            0,
            "System Integrity Protection status: enabled.\n"
        )));
        // The macos-15 runners (locked-macos log).
        assert!(!parse_status(&out(
            0,
            "System Integrity Protection status: disabled.\n"
        )));
        assert!(!parse_status(&out(
            0,
            "System Integrity Protection status: unknown (Custom Configuration).\n\n\
             Configuration:\n\tApple Internal: enabled\n\tKext Signing: enabled\n\
             \tFilesystem Protections: enabled\n\tDebugging Restrictions: enabled\n\
             \tDTrace Restrictions: enabled\n\tNVRAM Protections: enabled\n\
             \tBaseSystem Verification: enabled\n\tBoot-arg Restrictions: enabled\n\
             \tKernel Integrity Protections: enabled\n\tAuthenticated Root Requirement: enabled\n\n\
             This is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.\n"
        )));
        assert!(!parse_status(&out(
            0,
            "System Integrity Protection status: unknown.\n"
        )));
        // A failing csrutil, or one that says more than the line.
        assert!(!parse_status(&out(
            1,
            "System Integrity Protection status: enabled.\n"
        )));
        assert!(!parse_status(&out(
            0,
            "System Integrity Protection status: enabled.\nextra\n"
        )));
        assert!(!parse_status(&out(
            0,
            " System Integrity Protection status: enabled.\n"
        )));
        assert!(!parse_status(&out(0, "")));
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(true, false), SipVerdict::Enabled);
        assert_eq!(verdict(true, true), SipVerdict::Enabled);
        assert_eq!(verdict(false, true), SipVerdict::Bypassed);
        assert_eq!(verdict(false, false), SipVerdict::Required);
    }

    /// A release-like build ignores the seam whatever the environment.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_ignores_the_seam() {
        assert!(!seam_set());
    }

    /// The seam name exists only with debug assertions (this test does
    /// not compile otherwise) and is the documented one.
    #[cfg(debug_assertions)]
    #[test]
    fn seam_is_debug_only_and_named() {
        assert_eq!(SIP_SEAM, "SAIIFE_TEST_ALLOW_SIP_OFF");
        let src = include_str!("sip.rs");
        let at = src.find("pub const SIP_SEAM").unwrap();
        assert!(
            src[..at].trim_end().ends_with("#[cfg(debug_assertions)]"),
            "SIP_SEAM must be under cfg(debug_assertions)"
        );
    }
}
