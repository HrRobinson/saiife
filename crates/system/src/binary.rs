//! What kind of saiife binary locked mode runs (spec §9.2 A4).
//!
//! The managed hooks run `/opt/saiife/bin/saiife` as the agent user, in an
//! environment the agent can shape (Claude Code's settings `env`, for
//! one). A dynamically linked binary honours `LD_PRELOAD` and
//! `LD_LIBRARY_PATH` there, so the agent could run its own code inside the
//! hook. A build with debug assertions honours the `SAIIFE_EVAL_FAULT` test
//! seam, which can hang the guard past an agent's hook timeout. Locked mode
//! therefore wants the static release build. [`inspect`] reads both facts
//! from the file's bytes: the ELF program headers (no external tools), and
//! a build marker every saiife binary carries.

/// The first bytes of the build marker. Not a string literal anywhere: the
/// scanner reads them from [`BUILD_MARKER`] itself, so the only copy in a
/// saiife binary is the marker.
const MAGIC_LEN: usize = 16;

/// The build marker: 16 magic bytes, then `D` (debug assertions on) or `R`.
/// Kept in every binary that links this crate: [`inspect`] reads it.
#[used]
static BUILD_MARKER: [u8; MAGIC_LEN + 1] = [
    0xA7,
    0x5A,
    0x1F,
    0xE3,
    b's',
    b'a',
    b'i',
    b'i',
    b'f',
    b'e',
    b'-',
    b'b',
    0x00,
    0x9C,
    0x42,
    0xD1,
    if cfg!(debug_assertions) { b'D' } else { b'R' },
];

/// The marker of the build that is running (tests build fake binaries
/// with it).
pub fn build_marker(debug_assertions: bool) -> Vec<u8> {
    let m: &[u8; MAGIC_LEN + 1] = std::hint::black_box(&BUILD_MARKER);
    let mut v = m[..MAGIC_LEN].to_vec();
    v.push(if debug_assertions { b'D' } else { b'R' });
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linking {
    Static,
    /// Why it is dynamic: its interpreter or its library count.
    Dynamic(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Release,
    /// Built with debug assertions: the test seams are compiled in.
    DebugAssertions,
    /// No saiife build marker (or contradicting ones).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInfo {
    pub linking: Linking,
    pub profile: Profile,
}

impl BinaryInfo {
    /// What makes this binary unfit for locked mode, one phrase each;
    /// empty for a static release build.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Linking::Dynamic(why) = &self.linking {
            out.push(format!(
                "it is dynamically linked ({why}), so an agent could inject code \
                 into the hook through LD_PRELOAD"
            ));
        }
        match self.profile {
            Profile::Release => {}
            Profile::DebugAssertions => out.push(
                "it is a test build (debug assertions on: the SAIIFE_EVAL_FAULT test seam \
                 is compiled in)"
                    .to_string(),
            ),
            Profile::Unknown => out.push("it carries no saiife build marker".to_string()),
        }
        out
    }
}

/// The linking and build profile of the binary `bytes`. An error when it is
/// not an ELF executable this parser understands.
pub fn inspect(bytes: &[u8]) -> Result<BinaryInfo, String> {
    Ok(BinaryInfo {
        linking: linking(bytes)?,
        profile: profile(bytes),
    })
}

fn profile(bytes: &[u8]) -> Profile {
    let marker = build_marker(false);
    let magic = &marker[..MAGIC_LEN];
    let (mut debug, mut release) = (false, false);
    let mut i = 0;
    while let Some(off) = bytes[i..].iter().position(|&b| b == magic[0]) {
        let at = i + off;
        if bytes[at..].starts_with(magic) {
            match bytes.get(at + MAGIC_LEN) {
                Some(b'D') => debug = true,
                Some(b'R') => release = true,
                _ => {}
            }
        }
        i = at + 1;
    }
    match (debug, release) {
        (true, false) => Profile::DebugAssertions,
        (false, true) => Profile::Release,
        _ => Profile::Unknown,
    }
}

const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PN_XNUM: u16 = 0xFFFF;

/// Reads fixed-size integers of one ELF class and byte order.
struct Elf<'a> {
    b: &'a [u8],
    wide: bool,
    le: bool,
}

impl Elf<'_> {
    fn bytes<const N: usize>(&self, at: u64) -> Result<[u8; N], String> {
        let at = usize::try_from(at).map_err(|_| "offset out of range".to_string())?;
        let end = at.checked_add(N).ok_or("offset out of range")?;
        self.b
            .get(at..end)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "truncated ELF file".to_string())
    }
    fn u16(&self, at: u64) -> Result<u16, String> {
        let x = self.bytes::<2>(at)?;
        Ok(if self.le {
            u16::from_le_bytes(x)
        } else {
            u16::from_be_bytes(x)
        })
    }
    fn u32(&self, at: u64) -> Result<u32, String> {
        let x = self.bytes::<4>(at)?;
        Ok(if self.le {
            u32::from_le_bytes(x)
        } else {
            u32::from_be_bytes(x)
        })
    }
    fn u64(&self, at: u64) -> Result<u64, String> {
        let x = self.bytes::<8>(at)?;
        Ok(if self.le {
            u64::from_le_bytes(x)
        } else {
            u64::from_be_bytes(x)
        })
    }
    /// A word of this class: 8 bytes in ELF64, 4 in ELF32.
    fn word(&self, at: u64) -> Result<u64, String> {
        if self.wide {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }
}

/// Static unless a program header names an interpreter (`PT_INTERP`) or the
/// dynamic section needs a library (`DT_NEEDED`). A static PIE has a
/// dynamic section for its own relocations, without either.
fn linking(bytes: &[u8]) -> Result<Linking, String> {
    if bytes.len() < 16 || &bytes[..4] != b"\x7fELF" {
        return Err("not an ELF file".to_string());
    }
    let wide = match bytes[4] {
        1 => false,
        2 => true,
        c => return Err(format!("unknown ELF class {c}")),
    };
    let le = match bytes[5] {
        1 => true,
        2 => false,
        d => return Err(format!("unknown ELF byte order {d}")),
    };
    let e = Elf { b: bytes, wide, le };
    let e_type = e.u16(16)?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(format!("ELF type {e_type} is not an executable"));
    }
    let (phoff, phentsize, phnum) = if wide {
        (e.u64(0x20)?, e.u16(0x36)?, e.u16(0x38)?)
    } else {
        (u64::from(e.u32(0x1C)?), e.u16(0x2A)?, e.u16(0x2C)?)
    };
    if phnum == PN_XNUM {
        return Err("too many program headers".to_string());
    }
    let min_ent = if wide { 56 } else { 32 };
    if phnum > 0 && u64::from(phentsize) < min_ent {
        return Err(format!("program header size {phentsize} is too small"));
    }
    let mut interp = None;
    let mut needed = 0usize;
    for n in 0..u64::from(phnum) {
        let ph = phoff
            .checked_add(n * u64::from(phentsize))
            .ok_or("offset out of range")?;
        let p_type = e.u32(ph)?;
        let (offset, filesz) = if wide {
            (e.u64(ph + 8)?, e.u64(ph + 32)?)
        } else {
            (u64::from(e.u32(ph + 4)?), u64::from(e.u32(ph + 16)?))
        };
        match p_type {
            PT_INTERP => {
                let end = offset.checked_add(filesz).ok_or("offset out of range")?;
                let s = usize::try_from(offset)
                    .ok()
                    .zip(usize::try_from(end).ok())
                    .and_then(|(a, b)| bytes.get(a..b))
                    .ok_or("truncated ELF file")?;
                let s = s.split(|&c| c == 0).next().unwrap_or_default();
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            PT_DYNAMIC => {
                let ent = if wide { 16 } else { 8 };
                let half = ent / 2;
                for k in 0..filesz / ent {
                    let d = offset.checked_add(k * ent).ok_or("offset out of range")?;
                    match e.word(d)? {
                        DT_NULL => break,
                        DT_NEEDED => needed += 1,
                        _ => {}
                    }
                    // The value is not needed; it must still be in the file.
                    e.word(d + half)?;
                }
            }
            _ => {}
        }
    }
    Ok(match (interp, needed) {
        (Some(i), _) => Linking::Dynamic(format!("interpreter {i}")),
        (None, 0) => Linking::Static,
        (None, n) => Linking::Dynamic(format!(
            "needs {n} shared librar{}",
            if n == 1 { "y" } else { "ies" }
        )),
    })
}

/// The signature state of a Mach-O binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Unsigned,
    AdHoc,
    /// Not flagged ad-hoc, but no CMS blob either.
    NoCms,
    /// A CMS signature and no ad-hoc flag (a Developer ID build).
    Signed,
}

/// What locked mode needs to know about a macOS binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachInfo {
    pub hardened_runtime: bool,
    pub signature: Signature,
    pub profile: Profile,
}

impl MachInfo {
    /// The refusals, one phrase each; empty when the binary is fit.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.signature == Signature::Unsigned {
            out.push("it is not code-signed".to_string());
        } else if !self.hardened_runtime {
            out.push(
                "it is signed without the hardened runtime, so the agent could inject \
                 code into the hook through DYLD_INSERT_LIBRARIES"
                    .to_string(),
            );
        }
        match self.profile {
            Profile::Release => {}
            Profile::DebugAssertions => out.push(
                "it is a test build (debug assertions on: the SAIIFE_EVAL_FAULT test seam \
                 is compiled in)"
                    .to_string(),
            ),
            Profile::Unknown => out.push("it carries no saiife build marker".to_string()),
        }
        out
    }

    /// Things worth saying that do not refuse.
    pub fn warnings(&self) -> Vec<String> {
        match self.signature {
            Signature::AdHoc => {
                vec!["ad-hoc signature: not a Developer ID build (spec 5.3)".to_string()]
            }
            Signature::NoCms => vec!["no CMS signature present".to_string()],
            Signature::Unsigned | Signature::Signed => Vec::new(),
        }
    }
}

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
const CS_ADHOC: u32 = 0x2;
const CS_RUNTIME: u32 = 0x10000;
const MACH_HEADER_64: usize = 32;

/// The u32 at `at + add`, with every offset step checked.
fn rd(b: &[u8], at: usize, add: usize, big: bool) -> Result<u32, String> {
    let at = at.checked_add(add).ok_or("offset out of range")?;
    let end = at.checked_add(4).ok_or("offset out of range")?;
    let x: [u8; 4] = b
        .get(at..end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| "truncated Mach-O file".to_string())?;
    Ok(if big {
        u32::from_be_bytes(x)
    } else {
        u32::from_le_bytes(x)
    })
}

/// The signature and hardened-runtime flag of a thin 64-bit Mach-O, read
/// from its bytes (no `codesign`). A universal binary is refused.
///
/// This reads the flags the file claims; it does not verify the signature
/// (hashes, certificate chain). Every offset is bounds- and overflow-checked,
/// so hostile input gives an `Err`, never a panic.
pub fn inspect_macho(bytes: &[u8]) -> Result<MachInfo, String> {
    let magic = rd(bytes, 0, 0, false).map_err(|_| "not a Mach-O file".to_string())?;
    // Fat headers are big-endian on disk, so a little-endian read swaps them.
    if magic == FAT_MAGIC.swap_bytes() || magic == FAT_MAGIC_64.swap_bytes() {
        return Err(
            "universal binaries are not supported; use the per-architecture release".to_string(),
        );
    }
    if magic != MH_MAGIC_64 {
        return Err("not a 64-bit Mach-O file".to_string());
    }
    let profile = profile(bytes);
    let ncmds = rd(bytes, 16, 0, false)?;
    let mut at = MACH_HEADER_64;
    let mut sig = None;
    for _ in 0..ncmds {
        let cmd = rd(bytes, at, 0, false)?;
        let size = rd(bytes, at, 4, false)? as usize;
        if size < 8 {
            return Err("malformed load command".to_string());
        }
        if cmd == LC_CODE_SIGNATURE {
            sig = Some((
                rd(bytes, at, 8, false)? as usize,
                rd(bytes, at, 12, false)? as usize,
            ));
            break;
        }
        at = at.checked_add(size).ok_or("offset out of range")?;
    }
    let Some((off, len)) = sig else {
        return Ok(MachInfo {
            hardened_runtime: false,
            signature: Signature::Unsigned,
            profile,
        });
    };
    let end = off.checked_add(len).ok_or("offset out of range")?;
    let blob = bytes.get(off..end).ok_or("truncated Mach-O file")?;
    if rd(blob, 0, 0, true)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err("code signature is not an embedded SuperBlob".to_string());
    }
    let count = rd(blob, 8, 0, true)? as usize;
    let (mut flags, mut cms) = (None, false);
    for i in 0..count.min(64) {
        let ent = 12usize.saturating_add(i.saturating_mul(8));
        let (slot, so) = (rd(blob, ent, 0, true)?, rd(blob, ent, 4, true)? as usize);
        if slot == CSSLOT_CODEDIRECTORY {
            if rd(blob, so, 0, true)? != CSMAGIC_CODEDIRECTORY {
                return Err("code signature has no CodeDirectory".to_string());
            }
            flags = Some(rd(blob, so, 12, true)?);
        } else if slot == CSSLOT_SIGNATURESLOT {
            // A CMS blob is magic + length + data; empty means length 8.
            cms = rd(blob, so, 4, true)? > 8;
        }
    }
    let flags = flags.ok_or("code signature has no CodeDirectory")?;
    let signature = if flags & CS_ADHOC != 0 {
        Signature::AdHoc
    } else if !cms {
        Signature::NoCms
    } else {
        Signature::Signed
    };
    Ok(MachInfo {
        hardened_runtime: flags & CS_RUNTIME != 0,
        signature,
        profile,
    })
}

/// A minimal ELF64 little-endian executable for tests: a header, then a
/// `PT_INTERP` or a `PT_DYNAMIC` with `needed` `DT_NEEDED` entries when
/// asked, then the build marker (if `marker` is given).
#[doc(hidden)]
pub fn fake_elf(interp: Option<&str>, needed: usize, marker: Option<bool>) -> Vec<u8> {
    let mut phdrs: Vec<(u32, Vec<u8>)> = Vec::new();
    if let Some(i) = interp {
        let mut s = i.as_bytes().to_vec();
        s.push(0);
        phdrs.push((PT_INTERP, s));
    }
    // A static PIE has a dynamic section too, without DT_NEEDED.
    let mut dynamic = Vec::new();
    for _ in 0..needed {
        dynamic.extend_from_slice(&DT_NEEDED.to_le_bytes());
        dynamic.extend_from_slice(&1u64.to_le_bytes());
    }
    dynamic.extend_from_slice(&7u64.to_le_bytes()); // DT_RELA
    dynamic.extend_from_slice(&0u64.to_le_bytes());
    dynamic.extend_from_slice(&[0u8; 16]); // DT_NULL
    phdrs.push((PT_DYNAMIC, dynamic));

    let mut out = vec![0u8; 64];
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    out[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
    out[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    out[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    out[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    out[0x38..0x3A].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    let mut data_at = 64 + 56 * phdrs.len();
    let mut data = Vec::new();
    for (t, body) in &phdrs {
        let mut ph = vec![0u8; 56];
        ph[..4].copy_from_slice(&t.to_le_bytes());
        ph[8..16].copy_from_slice(&(data_at as u64).to_le_bytes());
        ph[32..40].copy_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&ph);
        data.extend_from_slice(body);
        data_at += body.len();
    }
    out.extend_from_slice(&data);
    if let Some(debug) = marker {
        out.extend_from_slice(b"padding");
        out.extend_from_slice(&build_marker(debug));
    }
    out
}

/// A thin Mach-O for tests: with `sig` (CodeDirectory flags, CMS blob)
/// one `LC_CODE_SIGNATURE`, then `marker` and the signature.
// Test support only: never in a release build.
#[cfg(any(test, debug_assertions))]
#[doc(hidden)]
pub fn fake_macho_with(sig: Option<(u32, bool)>, marker: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; MACH_HEADER_64];
    out[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    out[16..20].copy_from_slice(&u32::from(sig.is_some()).to_le_bytes());
    out[20..24].copy_from_slice(&16u32.to_le_bytes());
    if let Some((flags, cms)) = sig {
        let sig_off = (MACH_HEADER_64 + 16 + marker.len()) as u32;
        let mut cd = vec![0u8; 44];
        cd[..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&44u32.to_be_bytes());
        cd[12..16].copy_from_slice(&flags.to_be_bytes());
        let n: u32 = if cms { 2 } else { 1 };
        let base = 12 + 8 * n;
        let mut sb = CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes().to_vec();
        sb.extend_from_slice(&0u32.to_be_bytes());
        sb.extend_from_slice(&n.to_be_bytes());
        sb.extend_from_slice(&CSSLOT_CODEDIRECTORY.to_be_bytes());
        sb.extend_from_slice(&base.to_be_bytes());
        if cms {
            sb.extend_from_slice(&CSSLOT_SIGNATURESLOT.to_be_bytes());
            sb.extend_from_slice(&(base + 44).to_be_bytes());
        }
        sb.extend_from_slice(&cd);
        if cms {
            sb.extend_from_slice(&0xfade_0b01u32.to_be_bytes());
            sb.extend_from_slice(&12u32.to_be_bytes());
            sb.extend_from_slice(&[1, 2, 3, 4]);
        }
        let total = sb.len() as u32;
        sb[4..8].copy_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&sig_off.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(marker);
        out.extend_from_slice(&sb);
    } else {
        out.extend_from_slice(marker);
    }
    out
}

/// A thin Mach-O with the release build marker, for tests: unsigned
/// (`None`) or signed with `(adhoc, hardened_runtime, cms)`.
// Test support only: never in a release build.
#[cfg(any(test, debug_assertions))]
#[doc(hidden)]
pub fn fake_macho(sig: Option<(bool, bool, bool)>) -> Vec<u8> {
    let sig = sig.map(|(adhoc, runtime, cms)| {
        let mut flags = 0;
        if adhoc {
            flags |= CS_ADHOC;
        }
        if runtime {
            flags |= CS_RUNTIME;
        }
        (flags, cms)
    });
    fake_macho_with(sig, &build_marker(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_release_has_no_problems() {
        let b = fake_elf(None, 0, Some(false));
        let i = inspect(&b).unwrap();
        assert_eq!(i.linking, Linking::Static);
        assert_eq!(i.profile, Profile::Release);
        assert!(i.problems().is_empty());
    }

    #[test]
    fn interpreter_is_dynamic() {
        let b = fake_elf(Some("/lib64/ld-linux-x86-64.so.2"), 2, Some(false));
        let i = inspect(&b).unwrap();
        assert_eq!(
            i.linking,
            Linking::Dynamic("interpreter /lib64/ld-linux-x86-64.so.2".into())
        );
        assert!(i.problems()[0].contains("LD_PRELOAD"), "{:?}", i.problems());
    }

    #[test]
    fn needed_library_without_interpreter_is_dynamic() {
        let i = inspect(&fake_elf(None, 1, Some(false))).unwrap();
        assert_eq!(i.linking, Linking::Dynamic("needs 1 shared library".into()));
    }

    #[test]
    fn debug_marker_is_a_test_build() {
        let i = inspect(&fake_elf(None, 0, Some(true))).unwrap();
        assert_eq!(i.profile, Profile::DebugAssertions);
        assert!(i.problems()[0].contains("test build"));
    }

    #[test]
    fn missing_or_mixed_marker_is_unknown() {
        assert_eq!(
            inspect(&fake_elf(None, 0, None)).unwrap().profile,
            Profile::Unknown
        );
        let mut b = fake_elf(None, 0, Some(true));
        b.extend_from_slice(&build_marker(false));
        assert_eq!(inspect(&b).unwrap().profile, Profile::Unknown);
    }

    #[test]
    fn not_elf_and_truncated_are_errors() {
        assert_eq!(inspect(b"#!/bin/sh\n").unwrap_err(), "not an ELF file");
        let b = fake_elf(Some("/lib/ld.so"), 0, None);
        assert!(inspect(&b[..100]).is_err());
    }

    /// A thin Mach-O with one LC_CODE_SIGNATURE (CodeDirectory `flags`, and
    /// a CMS blob when `cms`), after the release build marker.
    fn macho_fixture(flags: u32, cms: bool) -> Vec<u8> {
        macho_with(Some((flags, cms)), &build_marker(false))
    }

    use super::fake_macho_with as macho_with;

    #[test]
    fn hardened_runtime_flag_read() {
        let on = inspect_macho(&macho_fixture(CS_RUNTIME, true)).unwrap();
        assert!(on.hardened_runtime);
        assert_eq!(on.signature, Signature::Signed);
        assert!(on.problems().is_empty() && on.warnings().is_empty());
        let off = inspect_macho(&macho_fixture(0, true)).unwrap();
        assert!(!off.hardened_runtime);
    }

    #[test]
    fn adhoc_is_warning_not_refusal() {
        let i = inspect_macho(&macho_fixture(CS_ADHOC | CS_RUNTIME, false)).unwrap();
        assert_eq!(i.signature, Signature::AdHoc);
        assert!(i.problems().is_empty());
        assert_eq!(
            i.warnings(),
            vec!["ad-hoc signature: not a Developer ID build (spec 5.3)".to_string()]
        );
    }

    #[test]
    fn unsigned_refused() {
        let i = inspect_macho(&macho_with(None, &build_marker(false))).unwrap();
        assert_eq!(i.signature, Signature::Unsigned);
        assert!(i.problems()[0].contains("not code-signed"));
    }

    #[test]
    fn no_runtime_refused() {
        let i = inspect_macho(&macho_fixture(CS_ADHOC, false)).unwrap();
        assert!(i.problems()[0].contains("hardened runtime"));
    }

    #[test]
    fn fat_binary_refused() {
        let mut b = FAT_MAGIC.to_be_bytes().to_vec();
        b.extend_from_slice(&[0; 60]);
        assert_eq!(
            inspect_macho(&b).unwrap_err(),
            "universal binaries are not supported; use the per-architecture release"
        );
    }

    #[test]
    fn elf_is_not_macho() {
        assert!(inspect_macho(&fake_elf(None, 0, Some(false))).is_err());
        assert!(inspect_macho(b"").is_err());
        let b = macho_fixture(CS_RUNTIME, true);
        assert!(inspect_macho(&b[..60]).is_err());
    }

    #[test]
    fn debug_marker_refused() {
        let b = macho_with(Some((CS_RUNTIME, true)), &build_marker(true));
        let i = inspect_macho(&b).unwrap();
        assert_eq!(i.profile, Profile::DebugAssertions);
        assert!(i.problems()[0].contains("test build"));
    }

    #[test]
    fn no_cms_without_adhoc_has_its_own_warning() {
        let i = inspect_macho(&macho_fixture(CS_RUNTIME, false)).unwrap();
        assert_eq!(i.signature, Signature::NoCms);
        assert_eq!(i.warnings(), vec!["no CMS signature present".to_string()]);
    }

    #[test]
    fn every_prefix_is_err_or_valid() {
        let b = macho_fixture(CS_RUNTIME, true);
        for n in 0..=b.len() {
            let _ = inspect_macho(&b[..n]);
        }
        assert!(inspect_macho(&b).is_ok());
    }

    fn put(b: &mut [u8], at: usize, v: u32, big: bool) {
        let x = if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        b[at..at + 4].copy_from_slice(&x);
    }

    #[test]
    fn hostile_mutations_do_not_panic() {
        let good = macho_fixture(CS_RUNTIME, true);
        let sb = u32::from_le_bytes(good[40..44].try_into().unwrap()) as usize;
        // (offset, value, big-endian)
        let cases: [(usize, u32, bool); 8] = [
            (36, 0, false),                // cmdsize 0
            (16, u32::MAX, false),         // huge ncmds
            (40, u32::MAX - 2, false),     // dataoff near u32::MAX
            (44, u32::MAX, false),         // datasize near u32::MAX
            (sb + 8, u32::MAX, true),      // huge SuperBlob count
            (sb + 16, u32::MAX, true),     // bad slot offset
            (sb + 28, 0xdead_beef, true),  // wrong CodeDirectory magic
            (sb + 24, u32::MAX - 3, true), // bad CMS slot offset
        ];
        for (at, v, big) in cases {
            let mut b = good.clone();
            put(&mut b, at, v, big);
            let r = inspect_macho(&b);
            // A huge ncmds is harmless: the signature command comes first.
            assert!(r.is_err() || at == 16, "case at {at}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn own_test_binary_parses() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(inspect_macho(&exe).is_ok());
    }

    #[test]
    fn this_test_binary_carries_its_own_marker() {
        // The test binary itself: built by cargo, debug or release.
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let want = if cfg!(debug_assertions) {
            Profile::DebugAssertions
        } else {
            Profile::Release
        };
        assert_eq!(profile(&exe), want);
    }
}
