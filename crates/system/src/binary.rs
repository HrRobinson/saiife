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
