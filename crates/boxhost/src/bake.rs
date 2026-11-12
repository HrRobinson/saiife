//! Host side of the base image bake: the cloud-init seed disk, the payload
//! disk, the Cloud Hypervisor argv for the bake VM and the serial-log check.
//! The guest side is `assets/box/bake/saiife-bake.sh`, which is only ever run
//! inside the bake VM. Tokio-free: external tools go through [`Tools`].

use crate::image::{is_sha256, parse_pinned_image, valid_apt_name, PinnedImage, Recipe};
use crate::tools::{Tool, Tools};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const BAKE_SCRIPT: &str = include_str!("../../../assets/box/bake/saiife-bake.sh");
pub const USER_DATA_TMPL: &str = include_str!("../../../assets/box/bake/user-data.tmpl");
pub const GROWROOT_UNIT: &str = include_str!("../../../assets/box/bake/saiife-growroot.service");

pub const SEED_BYTES: u64 = 4 * 1024 * 1024;
pub const PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct BakeInputs {
    pub saiife_bin: PathBuf,
    pub claude_bin: PathBuf,
    /// `assets/box/guest`
    pub guest_assets: PathBuf,
    pub recipe: Recipe,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, no line breaks.
pub(crate) fn base64(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The cloud-config with the bake script embedded as base64.
pub fn render_user_data(tmpl: &str, bake_sh: &str) -> String {
    let mut out = tmpl.replace("@SAIIFE_BAKE_B64@", &base64(bake_sh.as_bytes()));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The three-line `recipe.env`. Every value is re-checked with the recipe
/// rules, so the guest never sees free text.
pub fn recipe_env(recipe: &Recipe) -> Result<String, String> {
    for p in &recipe.packages {
        if !valid_apt_name(p) {
            return Err(format!("recipe.env: bad package name {p:?}"));
        }
    }
    let mut pulls = Vec::new();
    for i in &recipe.images {
        let digest = i.digest.strip_prefix("sha256:").unwrap_or("");
        if !is_sha256(digest) {
            return Err(format!("recipe.env: bad digest for image {:?}", i.name));
        }
        let pin = format!("{}@{}", i.name, i.digest);
        let PinnedImage { name, .. } = parse_pinned_image(&pin)?;
        if name != i.name || name.contains('=') || name.starts_with('-') {
            return Err(format!("recipe.env: bad image name {:?}", i.name));
        }
        pulls.push(pin);
    }
    Ok(format!(
        "APT_PACKAGES={}\nPULL_IMAGES={}\nDIRECT_KERNEL={}\n",
        recipe.packages.join(" "),
        pulls.join(" "),
        u8::from(recipe.direct_kernel)
    ))
}

fn run(tools: &Tools, t: Tool, args: &[&OsStr]) -> Result<(), String> {
    tools
        .run(t, args, TOOL_TIMEOUT)
        .map(|_| ())
        .map_err(|e| format!("{t:?}: {e:?}"))
}

fn sized_file(out: &Path, len: u64) -> Result<(), String> {
    let _ = fs::remove_file(out);
    let f = File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    f.set_len(len)
        .map_err(|e| format!("size {}: {e}", out.display()))
}

/// A staging directory next to `out`, removed on drop (success and failure).
struct Stage(PathBuf);

impl Stage {
    fn new(out: &Path, tag: &str) -> Result<Stage, String> {
        let parent = out.parent().unwrap_or_else(|| Path::new("."));
        let name = out.file_name().and_then(|n| n.to_str()).unwrap_or("disk");
        let dir = parent.join(format!(".{name}.{tag}-stage"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        Ok(Stage(dir))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A 4 MiB vfat image labelled CIDATA with user-data and meta-data.
pub fn make_seed(tools: &Tools, out: &Path, user_data: &str) -> Result<(), String> {
    let stage = Stage::new(out, "seed")?;
    let ud = stage.0.join("user-data");
    let md = stage.0.join("meta-data");
    fs::write(&ud, user_data).map_err(|e| format!("write user-data: {e}"))?;
    fs::write(&md, "instance-id: saiife-bake\nlocal-hostname: box\n")
        .map_err(|e| format!("write meta-data: {e}"))?;
    sized_file(out, SEED_BYTES)?;
    run(
        tools,
        Tool::MkfsVfat,
        &[OsStr::new("-n"), OsStr::new("CIDATA"), out.as_os_str()],
    )?;
    run(
        tools,
        Tool::Mcopy,
        &[
            OsStr::new("-i"),
            out.as_os_str(),
            ud.as_os_str(),
            md.as_os_str(),
            OsStr::new("::"),
        ],
    )
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let rd = fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for ent in rd {
        let ent = ent.map_err(|e| format!("read {}: {e}", src.display()))?;
        let p = ent.path();
        let to = dst.join(ent.file_name());
        let ft = ent
            .file_type()
            .map_err(|e| format!("stat {}: {e}", p.display()))?;
        if ft.is_dir() {
            copy_tree(&p, &to)?;
        } else if ft.is_file() {
            fs::copy(&p, &to).map_err(|e| format!("copy {}: {e}", p.display()))?;
        } else {
            return Err(format!(
                "guest assets: {} is neither a file nor a directory",
                p.display()
            ));
        }
    }
    Ok(())
}

/// A 512 MiB vfat image labelled SAIIFE: saiife, claude, guest/, recipe.env
/// and an empty out/ the guest writes its results into.
pub fn make_payload(tools: &Tools, out: &Path, inputs: &BakeInputs) -> Result<(), String> {
    let env = recipe_env(&inputs.recipe)?;
    let stage = Stage::new(out, "payload")?;
    let s = &stage.0;
    fs::copy(&inputs.saiife_bin, s.join("saiife"))
        .map_err(|e| format!("copy {}: {e}", inputs.saiife_bin.display()))?;
    fs::copy(&inputs.claude_bin, s.join("claude"))
        .map_err(|e| format!("copy {}: {e}", inputs.claude_bin.display()))?;
    copy_tree(&inputs.guest_assets, &s.join("guest"))?;
    fs::write(s.join("recipe.env"), env).map_err(|e| format!("write recipe.env: {e}"))?;
    fs::create_dir(s.join("out")).map_err(|e| format!("create out: {e}"))?;
    fs::write(s.join("out").join(".keep"), "").map_err(|e| format!("write .keep: {e}"))?;
    sized_file(out, PAYLOAD_BYTES)?;
    run(
        tools,
        Tool::MkfsVfat,
        &[OsStr::new("-n"), OsStr::new("SAIIFE"), out.as_os_str()],
    )?;
    let names = ["saiife", "claude", "guest", "recipe.env", "out"];
    let mut args: Vec<OsString> = vec!["-s".into(), "-i".into(), out.into()];
    args.extend(names.iter().map(|n| s.join(n).into_os_string()));
    args.push("::".into());
    let refs: Vec<&OsStr> = args.iter().map(|a| a.as_os_str()).collect();
    run(tools, Tool::Mcopy, &refs)
}

/// The Cloud Hypervisor arguments (after the binary) for the bake VM: 2
/// vCPU, 4096 MiB shared memory, firmware boot, three raw disks, a
/// vhost-user NIC served by passt, serial to a file and no vsock. The API
/// socket is included as in the spike's `ch_launch`.
///
/// Paths must not contain ',' or '=' (CH option syntax); the caller refuses
/// such paths, this function only `debug_assert!`s it.
pub fn bake_argv(
    base: &Path,
    seed: &Path,
    payload: &Path,
    fw: &Path,
    work: &Path,
) -> Vec<OsString> {
    for p in [base, seed, payload, fw, work] {
        debug_assert!(
            !p.to_string_lossy().contains([',', '=']),
            "path with ',' or '=' in the bake argv: {}",
            p.display()
        );
    }
    let kv = |k: &str, p: &Path| -> OsString {
        let mut s = OsString::from(k);
        s.push(p);
        s
    };
    let disk = |p: &Path| -> OsString {
        let mut s = kv("path=", p);
        s.push(",image_type=raw");
        s
    };
    let sock = |name: &str| -> PathBuf { work.join(name) };
    let net = kv("vhost_user=true,socket=", &sock("passt.sock"));
    vec![
        "--firmware".into(),
        fw.into(),
        "--disk".into(),
        disk(base),
        disk(seed),
        disk(payload),
        "--cpus".into(),
        "boot=2".into(),
        "--memory".into(),
        "size=4096M,shared=on".into(),
        "--net".into(),
        net,
        "--serial".into(),
        kv("file=", &sock("serial.log")),
        "--console".into(),
        "off".into(),
        "--api-socket".into(),
        kv("path=", &sock("ch.sock")),
    ]
}

/// Success only when `SAIIFE-BAKE-OK` is on a line of its own (CRs removed);
/// the `+ echo SAIIFE-BAKE-OK` trace of `set -x` does not count.
pub fn bake_check(serial_log: &str) -> bool {
    serial_log
        .split('\n')
        .any(|l| l.replace('\r', "") == "SAIIFE-BAKE-OK")
}

/// True when the file is an ELF64 little-endian binary without a PT_INTERP
/// program header. Not an ELF file is an error.
pub fn is_static_elf(path: &Path) -> Result<bool, String> {
    let e = |m: &str| format!("{}: {m}", path.display());
    let mut f = File::open(path).map_err(|x| e(&x.to_string()))?;
    let mut h = [0u8; 64];
    f.read_exact(&mut h).map_err(|_| e("not an ELF file"))?;
    if &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
        return Err(e("not an ELF64 little-endian file"));
    }
    let u16at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]) as usize;
    let phoff = u64::from_le_bytes(h[32..40].try_into().unwrap());
    let phentsize = u16at(54);
    let phnum = u16at(56);
    if phnum > 256 {
        return Err(e("too many program headers"));
    }
    if phnum > 0 && phentsize < 4 {
        return Err(e("bad program header size"));
    }
    let len = f.metadata().map_err(|x| e(&x.to_string()))?.len();
    let total = (phnum * phentsize) as u64;
    if phoff.checked_add(total).is_none_or(|end| end > len) {
        return Err(e("program headers outside the file"));
    }
    let mut buf = vec![0u8; total as usize];
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(phoff)).map_err(|x| e(&x.to_string()))?;
    f.read_exact(&mut buf).map_err(|x| e(&x.to_string()))?;
    for i in 0..phnum {
        let t = u32::from_le_bytes(buf[i * phentsize..i * phentsize + 4].try_into().unwrap());
        if t == 3 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Copy `::out/<name>` from the payload disk to `dest`.
pub fn read_out(tools: &Tools, payload: &Path, name: &str, dest: &Path) -> Result<(), String> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        return Err(format!("read_out: bad file name {name:?}"));
    }
    let src = OsString::from(format!("::out/{name}"));
    run(
        tools,
        Tool::Mcopy,
        &[
            OsStr::new("-n"),
            OsStr::new("-i"),
            payload.as_os_str(),
            src.as_os_str(),
            dest.as_os_str(),
        ],
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake(dir: &Path, name: &str, log: &Path) -> PathBuf {
        let p = dir.join(name);
        // one line per call: tool name, then each argument
        let body = format!(
            "#!/bin/sh\nprintf '%s' '{name}' >>'{l}'\nfor a in \"$@\"; do printf ' %s' \"$a\" >>'{l}'; done\nprintf '\\n' >>'{l}'\n",
            l = log.display()
        );
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn world() -> (tempfile::TempDir, Tools, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("calls.log");
        let mk = fake(d.path(), "mkfs.vfat", &log);
        let mc = fake(d.path(), "mcopy", &log);
        let env = move |k: &str| -> Option<OsString> {
            match k {
                "SAIIFE_TOOL_MKFS_VFAT" => Some(mk.clone().into_os_string()),
                "SAIIFE_TOOL_MCOPY" => Some(mc.clone().into_os_string()),
                _ => None,
            }
        };
        let tools = Tools::system(d.path()).with_env(&env);
        (d, tools, log)
    }

    fn recipe() -> Recipe {
        Recipe {
            ubuntu_release: "release-1".into(),
            ubuntu_sha256: "0".repeat(64),
            packages: vec!["docker.io".into(), "git".into()],
            images: vec![PinnedImage {
                name: "busybox".into(),
                digest: format!("sha256:{}", "b".repeat(64)),
            }],
            claude: crate::image::ClaudePin {
                version: "1".into(),
                url: "u".into(),
                sha256: "a".repeat(64),
            },
            direct_kernel: true,
        }
    }

    #[test]
    fn user_data_embeds_the_script() {
        let ud = render_user_data(USER_DATA_TMPL, BAKE_SCRIPT);
        assert!(!ud.contains('@'));
        let line = ud
            .lines()
            .find_map(|l| l.trim().strip_prefix("content: "))
            .unwrap();
        // decode with a table independent of the encoder
        let mut bits = 0u32;
        let mut n = 0;
        let mut out = Vec::new();
        for c in line.bytes().filter(|c| *c != b'=') {
            let v = B64.iter().position(|x| *x == c).unwrap() as u32;
            bits = (bits << 6) | v;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
                bits &= (1 << n) - 1;
            }
        }
        assert_eq!(String::from_utf8(out).unwrap(), BAKE_SCRIPT);
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert!(ud.contains("users: []"));
    }

    #[test]
    fn growroot_unit_matches_the_script() {
        for l in GROWROOT_UNIT.lines() {
            assert!(BAKE_SCRIPT.contains(l), "{l}");
        }
        assert!(BAKE_SCRIPT.contains("echo SAIIFE-BAKE-OK >\"$TTY\""));
    }

    #[test]
    fn script_pulls_before_the_proxy_config_and_is_glob_safe() {
        let main = BAKE_SCRIPT.split("\nmain() {").nth(1).unwrap();
        let pull = main.find("  pull_images\n").unwrap();
        let conf = main.find("  write_docker_config\n").unwrap();
        assert!(pull < conf);
        let trim = BAKE_SCRIPT
            .split("\ntrim() {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(!trim.contains("daemon.json"));
        assert!(BAKE_SCRIPT.contains("systemctl enable -- \"$u\""));
        assert!(BAKE_SCRIPT.contains("^[A-Za-z0-9][A-Za-z0-9@._-]*$"));
        assert!(BAKE_SCRIPT.contains("read -ra pkgs"));
        assert!(BAKE_SCRIPT.contains("read -ra imgs"));
        assert!(!BAKE_SCRIPT.contains("$APT_PACKAGES\n"));
    }

    #[test]
    fn seed_and_payload_call_mkfs_and_mcopy() {
        let (d, tools, log) = world();
        let seed = d.path().join("seed.img");
        make_seed(&tools, &seed, "#cloud-config\n").unwrap();
        assert_eq!(fs::metadata(&seed).unwrap().len(), SEED_BYTES);

        let saiife = d.path().join("saiife-bin");
        let claude = d.path().join("claude-bin");
        fs::write(&saiife, "s").unwrap();
        fs::write(&claude, "c").unwrap();
        let g = d.path().join("guest");
        fs::create_dir_all(g.join("units")).unwrap();
        fs::write(g.join("units/a.service"), "x").unwrap();
        let payload = d.path().join("payload.img");
        let inputs = BakeInputs {
            saiife_bin: saiife,
            claude_bin: claude,
            guest_assets: g,
            recipe: recipe(),
        };
        make_payload(&tools, &payload, &inputs).unwrap();
        assert_eq!(fs::metadata(&payload).unwrap().len(), PAYLOAD_BYTES);

        let calls = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), 4, "{calls}");
        assert_eq!(lines[0], format!("mkfs.vfat -n CIDATA {}", seed.display()));
        assert!(lines[1].starts_with(&format!("mcopy -i {} ", seed.display())));
        assert!(lines[1].contains("user-data") && lines[1].contains("meta-data"));
        assert!(lines[1].ends_with(" ::"));
        assert_eq!(
            lines[2],
            format!("mkfs.vfat -n SAIIFE {}", payload.display())
        );
        assert!(lines[3].starts_with(&format!("mcopy -s -i {} ", payload.display())));
        for n in ["/saiife", "/claude", "/guest", "/recipe.env", "/out"] {
            assert!(lines[3].contains(&format!("{n} ")), "{n}: {}", lines[3]);
        }
        assert!(lines[3].ends_with(" ::"));
        // staging dirs are gone
        let left: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with("-stage"))
            .collect();
        assert!(left.is_empty());
    }

    #[test]
    fn staging_is_removed_on_failure() {
        let (d, _tools, _log) = world();
        let failing = d.path().join("failing.sh");
        fs::write(&failing, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&failing, fs::Permissions::from_mode(0o755)).unwrap();
        let f2 = failing.clone();
        let env = move |k: &str| -> Option<OsString> {
            (k == "SAIIFE_TOOL_MKFS_VFAT").then(|| f2.clone().into_os_string())
        };
        let tools = Tools::system(d.path()).with_env(&env);
        let r = make_seed(&tools, &d.path().join("seed.img"), "x");
        assert!(r.is_err(), "{r:?}");
        assert!(!fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with("-stage")));
    }

    #[test]
    fn bake_argv_is_pinned() {
        let a = bake_argv(
            Path::new("/i/base.raw"),
            Path::new("/w/seed.img"),
            Path::new("/w/payload.img"),
            Path::new("/v/CLOUDHV.fd"),
            Path::new("/w"),
        );
        let got: Vec<String> = a.iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let want = [
            "--firmware",
            "/v/CLOUDHV.fd",
            "--disk",
            "path=/i/base.raw,image_type=raw",
            "path=/w/seed.img,image_type=raw",
            "path=/w/payload.img,image_type=raw",
            "--cpus",
            "boot=2",
            "--memory",
            "size=4096M,shared=on",
            "--net",
            "vhost_user=true,socket=/w/passt.sock",
            "--serial",
            "file=/w/serial.log",
            "--console",
            "off",
            "--api-socket",
            "path=/w/ch.sock",
        ];
        assert_eq!(got, want);
        assert!(!got.iter().any(|s| s.contains("vsock")));
    }

    #[test]
    fn marker_must_be_a_line_of_its_own() {
        assert!(!bake_check("+ echo SAIIFE-BAKE-OK\r\n"));
        assert!(!bake_check("x SAIIFE-BAKE-OK\n"));
        assert!(!bake_check("SAIIFE-BAKE-OK extra\n"));
        assert!(bake_check("boot\r\nSAIIFE-BAKE-OK\r\n"));
        assert!(bake_check("SAIIFE-BAKE-OK\r"));
        assert!(!bake_check(""));
    }

    fn elf(interp: bool) -> Vec<u8> {
        let mut v = vec![0u8; 64 + 2 * 56];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        v[54..56].copy_from_slice(&56u16.to_le_bytes());
        v[56..58].copy_from_slice(&2u16.to_le_bytes());
        v[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        let t: u32 = if interp { 3 } else { 6 };
        v[64 + 56..64 + 60].copy_from_slice(&t.to_le_bytes());
        v
    }

    #[test]
    fn static_elf_check() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("b");
        fs::write(&p, elf(false)).unwrap();
        assert_eq!(is_static_elf(&p), Ok(true));
        fs::write(&p, elf(true)).unwrap();
        assert_eq!(is_static_elf(&p), Ok(false));
        fs::write(&p, b"#!/bin/sh\n").unwrap();
        assert!(is_static_elf(&p).is_err());
        let mut big = elf(false);
        big[56..58].copy_from_slice(&257u16.to_le_bytes());
        fs::write(&p, big).unwrap();
        assert!(is_static_elf(&p).is_err());
        let mut cut = elf(false);
        cut.truncate(100);
        fs::write(&p, cut).unwrap();
        assert!(is_static_elf(&p).is_err());
    }

    #[test]
    fn recipe_env_holds_only_checked_values() {
        let r = recipe();
        let env = recipe_env(&r).unwrap();
        assert_eq!(
            env,
            format!(
                "APT_PACKAGES=docker.io git\nPULL_IMAGES=busybox@sha256:{}\nDIRECT_KERNEL=1\n",
                "b".repeat(64)
            )
        );
        let mut bad = recipe();
        bad.packages.push("x; rm -rf /".into());
        assert!(recipe_env(&bad).is_err());
        let mut bad = recipe();
        bad.images[0].digest = "sha256:zz".into();
        assert!(recipe_env(&bad).is_err());
        let mut bad = recipe();
        bad.images[0].name = "a b".into();
        assert!(recipe_env(&bad).is_err());
        let mut bad = recipe();
        bad.images[0].name = "a=b".into();
        assert!(recipe_env(&bad).is_err());
    }

    #[test]
    fn read_out_checks_the_name_and_calls_mcopy() {
        let (d, tools, log) = world();
        let p = d.path().join("payload.img");
        let dest = d.path().join("packages.txt");
        for bad in ["", ".keep", "a/b", "a b", "..", "x;y"] {
            assert!(read_out(&tools, &p, bad, &dest).is_err(), "{bad}");
        }
        read_out(&tools, &p, "packages.txt", &dest).unwrap();
        let calls = fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls.trim(),
            format!(
                "mcopy -n -i {} ::out/packages.txt {}",
                p.display(),
                dest.display()
            )
        );
    }
}
