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
    /// The optional agent downloads, verified against their pins.
    pub agents: AgentArchives,
}

/// The optional agent downloads (plan 42 D10), already in the cache and
/// verified. Whether the bake installs an agent comes only from which of
/// these are in the payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentArchives {
    /// `codex.tar.gz`
    pub codex: Option<PathBuf>,
    /// `gemini.zip` and the `node.tar.xz` it runs on.
    pub gemini: Option<(PathBuf, PathBuf)>,
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

/// A generated payload file's contents.
pub type FileBody = fn() -> String;

/// The payload files of git's ssh wrapper, its ssh config and the system
/// git config (FU2 fix round 5), with their contents. Baked with Claude
/// Code's managed settings, which name the wrapper.
pub const CLAUDE_GIT_FILES: [(&str, FileBody); 3] = [
    ("saiife-ssh", crate::guest::saiife_ssh_wrapper),
    ("saiife-ssh-config", crate::guest::saiife_ssh_config),
    ("saiife-gitconfig", crate::guest::system_gitconfig),
];

/// A 512 MiB vfat image labelled SAIIFE: saiife, claude,
/// `claude-managed-settings.json` (FU2), git's ssh wrapper, ssh config and
/// system git config ([`CLAUDE_GIT_FILES`]), guest/, recipe.env and an empty
/// out/ the guest writes its results into. With Codex:
/// `codex.tar.gz`, `codex-requirements.toml` and
/// `codex-managed-config.toml`; with Gemini: `gemini.zip`,
/// `node.tar.xz`, `gemini-system-settings.json` and
/// `gemini-user-settings.json` (plan 42 D10, R14).
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
    let mut names = vec![
        "saiife",
        "claude",
        "claude-managed-settings.json",
        "saiife-ssh",
        "saiife-ssh-config",
        "saiife-gitconfig",
        "guest",
        "recipe.env",
        "out",
    ];
    let copy = |src: &Path, name: &str| {
        fs::copy(src, s.join(name)).map_err(|e| format!("copy {}: {e}", src.display()))
    };
    let write = |name: &str, body: String| {
        fs::write(s.join(name), body).map_err(|e| format!("write {name}: {e}"))
    };
    // Claude Code is always in the image, so its managed settings are too
    write(
        "claude-managed-settings.json",
        crate::guest::claude_managed_settings(),
    )?;
    for (name, body) in CLAUDE_GIT_FILES {
        write(name, body())?;
    }
    if let Some(codex) = &inputs.agents.codex {
        copy(codex, "codex.tar.gz")?;
        write(
            "codex-requirements.toml",
            crate::guest::codex_requirements(),
        )?;
        write(
            "codex-managed-config.toml",
            crate::guest::codex_managed_config(),
        )?;
        names.extend([
            "codex.tar.gz",
            "codex-requirements.toml",
            "codex-managed-config.toml",
        ]);
    }
    if let Some((gemini, node)) = &inputs.agents.gemini {
        copy(gemini, "gemini.zip")?;
        copy(node, "node.tar.xz")?;
        write(
            "gemini-system-settings.json",
            crate::guest::gemini_system_settings(),
        )?;
        write(
            "gemini-user-settings.json",
            crate::guest::gemini_user_settings(),
        )?;
        names.extend([
            "gemini.zip",
            "node.tar.xz",
            "gemini-system-settings.json",
            "gemini-user-settings.json",
        ]);
    }
    fs::create_dir(s.join("out")).map_err(|e| format!("create out: {e}"))?;
    fs::write(s.join("out").join(".keep"), "").map_err(|e| format!("write .keep: {e}"))?;
    sized_file(out, PAYLOAD_BYTES)?;
    run(
        tools,
        Tool::MkfsVfat,
        &[OsStr::new("-n"), OsStr::new("SAIIFE"), out.as_os_str()],
    )?;
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
    if &h[..4] != b"\x7fELF" {
        return Err(e("not an ELF file"));
    }
    let u16at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]) as usize;
    // ELFCLASS64, little-endian, e_machine EM_X86_64 (62).
    if h[4] != 2 || h[5] != 1 || u16at(18) != 62 {
        return Err(e(
            "not an x86-64 ELF (a 64-bit little-endian EM_X86_64 file)",
        ));
    }
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
            codex: None,
            gemini: None,
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
        let store = main.find("  write_docker_store_config\n").unwrap();
        let pull = main.find("  pull_images\n").unwrap();
        assert!(store < pull);
        let start_fn = BAKE_SCRIPT
            .split("\nstart_docker() {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(start_fn.contains("systemctl restart docker.service"));
        assert!(!start_fn.contains("systemctl start docker.service"));
        let store_fn = BAKE_SCRIPT
            .split("\nwrite_docker_store_config() {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(store_fn.contains("containerd-snapshotter") && !store_fn.contains("proxies"));
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

    fn script_fn(name: &str) -> &'static str {
        BAKE_SCRIPT
            .split(&format!("\n{name}() {{"))
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap()
    }

    #[test]
    fn kvm_kernel_only_for_direct_boot() {
        assert!(!crate::image::DEFAULT_RECIPE.contains("linux-image-kvm"));
        let out = script_fn("export_outputs");
        let direct = out
            .split("if [ \"$DIRECT_KERNEL\" = 1 ]; then")
            .nth(1)
            .unwrap();
        let install = direct
            .find("apt-get install -y --no-install-recommends linux-image-kvm")
            .unwrap();
        assert!(install < direct.find("cp \"$k\"").unwrap());
        assert_eq!(BAKE_SCRIPT.matches("linux-image-kvm\n").count(), 1);
    }

    #[test]
    fn script_generalises_the_image() {
        let g = script_fn("generalise");
        for l in [
            "cloud-init clean --logs --seed",
            "command -v cloud-init",
            "truncate -s 0 /etc/machine-id",
            "rm -f /var/lib/dbus/machine-id",
            "ln -s /etc/machine-id /var/lib/dbus/machine-id",
            "rm -f /etc/ssh/ssh_host_*",
            "systemctl mask ssh.service ssh.socket",
            "rm -f /var/lib/docker/engine-id",
        ] {
            assert!(g.contains(l), "{l}");
        }
        let main = script_fn("main");
        let pull = main.find("  pull_images\n").unwrap();
        let gen = main.find("  generalise\n").unwrap();
        let disable = main.find("touch /etc/cloud/cloud-init.disabled").unwrap();
        assert!(pull < gen && gen < disable);
        assert!(script_fn("pull_images").contains("systemctl stop docker.service docker.socket"));
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
            agents: AgentArchives::default(),
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

    /// A fake mcopy that keeps a copy of every file it is handed in
    /// `<dir>/seen/` and logs its arguments.
    fn keeping_world() -> (tempfile::TempDir, Tools, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("calls.log");
        let seen = d.path().join("seen");
        fs::create_dir(&seen).unwrap();
        let mk = fake(d.path(), "mkfs.vfat", &log);
        let mc = d.path().join("mcopy");
        fs::write(
            &mc,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do printf ' %s' \"$a\" >>'{l}'; if [ -f \"$a\" ]; then cp \"$a\" '{s}/'; fi; done\nprintf '\\n' >>'{l}'\n",
                l = log.display(),
                s = seen.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&mc, fs::Permissions::from_mode(0o755)).unwrap();
        let env = move |k: &str| -> Option<OsString> {
            match k {
                "SAIIFE_TOOL_MKFS_VFAT" => Some(mk.clone().into_os_string()),
                "SAIIFE_TOOL_MCOPY" => Some(mc.clone().into_os_string()),
                _ => None,
            }
        };
        let tools = Tools::system(d.path()).with_env(&env);
        (d, tools, log, seen)
    }

    #[test]
    fn payload_carries_enabled_agents() {
        use crate::guest;
        const AGENT_FILES: [&str; 7] = [
            "codex.tar.gz",
            "codex-requirements.toml",
            "codex-managed-config.toml",
            "gemini.zip",
            "node.tar.xz",
            "gemini-system-settings.json",
            "gemini-user-settings.json",
        ];
        let cases: [(bool, bool); 4] = [(false, false), (true, false), (false, true), (true, true)];
        for (codex, gemini) in cases {
            let (d, tools, log, seen) = keeping_world();
            let p = d.path();
            for (n, body) in [
                ("saiife-bin", "s"),
                ("claude-bin", "c"),
                ("codex-x", "codex archive"),
                ("gemini-x", "gemini archive"),
                ("node-x", "node archive"),
            ] {
                fs::write(p.join(n), body).unwrap();
            }
            fs::create_dir(p.join("guest")).unwrap();
            let inputs = BakeInputs {
                saiife_bin: p.join("saiife-bin"),
                claude_bin: p.join("claude-bin"),
                guest_assets: p.join("guest"),
                recipe: recipe(),
                agents: AgentArchives {
                    codex: codex.then(|| p.join("codex-x")),
                    gemini: gemini.then(|| (p.join("gemini-x"), p.join("node-x"))),
                },
            };
            make_payload(&tools, &p.join("payload.img"), &inputs).unwrap();
            let calls = fs::read_to_string(&log).unwrap();
            let copy = calls.lines().last().unwrap();
            let want: Vec<&str> = AGENT_FILES
                .iter()
                .copied()
                .filter(|n| {
                    if n.starts_with("codex") {
                        codex
                    } else {
                        gemini
                    }
                })
                .collect();
            for n in AGENT_FILES {
                let there = copy.contains(&format!("/{n} "));
                assert_eq!(there, want.contains(&n), "{codex} {gemini} {n}: {copy}");
                assert_eq!(seen.join(n).exists(), want.contains(&n), "{n}");
            }
            let read = |n: &str| fs::read_to_string(seen.join(n)).unwrap();
            if codex {
                assert_eq!(read("codex.tar.gz"), "codex archive");
                assert_eq!(read("codex-requirements.toml"), guest::codex_requirements());
                assert_eq!(
                    read("codex-managed-config.toml"),
                    guest::codex_managed_config()
                );
            }
            if gemini {
                assert_eq!(read("gemini.zip"), "gemini archive");
                assert_eq!(read("node.tar.xz"), "node archive");
                assert_eq!(
                    read("gemini-system-settings.json"),
                    guest::gemini_system_settings()
                );
                assert_eq!(
                    read("gemini-user-settings.json"),
                    guest::gemini_user_settings()
                );
            }
            // Claude Code is always in the image, so its managed settings
            // are too (FU2)
            assert!(copy.contains("/claude-managed-settings.json "), "{copy}");
            assert_eq!(
                read("claude-managed-settings.json"),
                guest::claude_managed_settings()
            );
            // and git's ssh wrapper, ssh config and system git config
            // (FU2 fix round 5)
            for (n, body) in CLAUDE_GIT_FILES {
                assert!(copy.contains(&format!("/{n} ")), "{n}: {copy}");
                assert_eq!(read(n), body(), "{n}");
            }
            assert_eq!(read("saiife-ssh"), guest::saiife_ssh_wrapper());
            assert_eq!(read("saiife-ssh-config"), guest::saiife_ssh_config());
            assert_eq!(read("saiife-gitconfig"), guest::system_gitconfig());
            // recipe.env does not change with the agents (D10)
            assert_eq!(read("recipe.env"), recipe_env(&recipe()).unwrap());
        }
    }

    #[test]
    fn bake_script_checks() {
        use crate::guest;
        let d = tempfile::tempdir().unwrap();
        let sh = d.path().join("saiife-bake.sh");
        fs::write(&sh, BAKE_SCRIPT).unwrap();
        // syntax only: the script is never run on the host
        let st = std::process::Command::new("bash")
            .arg("-n")
            .arg(&sh)
            .status()
            .unwrap();
        assert!(st.success(), "bash -n");
        assert!(BAKE_SCRIPT.contains("\nset -euxo pipefail\n"));
        for l in [
            "install_agents",
            "--no-same-owner",
            "python3 -I -m zipfile -e",
            "codex-x86_64-unknown-linux-musl",
            "--strip-components=1",
            "exec /opt/saiife-node/bin/node %s \"$@\"",
        ] {
            assert!(BAKE_SCRIPT.contains(l), "{l}");
        }
        // after the agent user (its group owns the gemini dir), before trim
        let main = script_fn("main");
        let user = main.find("  make_agent_user\n").unwrap();
        let agents = main.find("  install_agents\n").unwrap();
        assert!(user < agents && agents < main.find("  trim\n").unwrap());
        // Claude Code's managed settings: always, from install_agents (FU2)
        let claude = script_fn("install_claude_managed");
        assert!(claude.contains(&format!("\"{}\"", guest::CLAUDE_MANAGED_SETTINGS_PATH)));
        // git's ssh files go in with the managed settings that name them, so
        // the claude_managed_settings capability covers them (FU2 fix 5)
        for path in [
            guest::CLAUDE_GIT_SSH,
            guest::SAIIFE_SSH_CONFIG_PATH,
            guest::SYSTEM_GITCONFIG_PATH,
        ] {
            assert!(claude.contains(&format!("\"{path}\"")), "{path}");
        }
        let agents_fn = script_fn("install_agents");
        let first = agents_fn.lines().nth(1).map(str::trim);
        assert_eq!(first, Some("install_claude_managed"), "{agents_fn}");
        // the R14 tree, with its owners and modes
        for path in [
            guest::CLAUDE_MANAGED_SETTINGS_PATH,
            guest::CODEX_REQUIREMENTS_PATH,
            guest::CODEX_MANAGED_CONFIG_PATH,
            guest::GEMINI_SYSTEM_SETTINGS_PATH,
            guest::GEMINI_HOME,
            guest::GEMINI_USER_SETTINGS_PATH,
        ] {
            assert!(BAKE_SCRIPT.contains(&format!("\"{path}\"")), "{path}");
        }
        let lines: Vec<&str> = BAKE_SCRIPT.lines().map(str::trim).collect();
        let has = |l: &str| lines.contains(&l);
        let home = guest::GEMINI_HOME;
        for l in [
            "install -d -o root -g root -m 0755 \"/etc/claude-code\"".to_string(),
            "install -d -o root -g root -m 0755 \"/usr/local/libexec\"".to_string(),
            format!(
                "install -o root -g root -m 0755 \"$MNT/saiife-ssh\" \"{}\"",
                guest::CLAUDE_GIT_SSH
            ),
            "install -d -o root -g root -m 0755 \"/etc/ssh\"".to_string(),
            format!(
                "install -o root -g root -m 0644 \"$MNT/saiife-ssh-config\" \"{}\"",
                guest::SAIIFE_SSH_CONFIG_PATH
            ),
            format!(
                "install -o root -g root -m 0644 \"$MNT/saiife-gitconfig\" \"{}\"",
                guest::SYSTEM_GITCONFIG_PATH
            ),
            format!(
                "install -o root -g root -m 0644 \"$MNT/claude-managed-settings.json\" \"{}\"",
                guest::CLAUDE_MANAGED_SETTINGS_PATH
            ),
            "install -d -o root -g root -m 0755 \"/etc/codex\"".to_string(),
            format!(
                "install -o root -g root -m 0644 \"$MNT/codex-requirements.toml\" \"{}\"",
                guest::CODEX_REQUIREMENTS_PATH
            ),
            format!(
                "install -o root -g root -m 0644 \"$MNT/codex-managed-config.toml\" \"{}\"",
                guest::CODEX_MANAGED_CONFIG_PATH
            ),
            "install -d -o root -g root -m 0755 \"/etc/gemini-cli\"".to_string(),
            format!(
                "install -o root -g root -m 0644 \"$MNT/gemini-system-settings.json\" \"{}\"",
                guest::GEMINI_SYSTEM_SETTINGS_PATH
            ),
            format!("install -d -o root -g root -m 0755 \"{home}\""),
            format!("install -d -o root -g agent -m 1775 \"{home}/.gemini\""),
            format!(
                "install -o root -g root -m 0644 \"$MNT/gemini-user-settings.json\" \"{}\"",
                guest::GEMINI_USER_SETTINGS_PATH
            ),
            format!("install -o root -g root -m 0644 /dev/null \"{home}/.gemini/.env\""),
            format!("install -d -o root -g root -m 0755 \"{home}/.gemini/extensions\""),
        ] {
            assert!(has(&l), "missing line: {l}");
        }
        assert!(
            guest::GEMINI_USER_SETTINGS_PATH.starts_with(&format!("{home}/.gemini/")),
            "the user settings live in the baked home"
        );
        // the archives are data: nothing from them is sourced or evaluated
        let agents_fns = [
            "install_agents",
            "install_claude_managed",
            "install_codex",
            "install_gemini",
        ]
        .map(script_fn)
        .concat();
        for bad in ["eval ", "source ", ". \"$", "bash \"$"] {
            assert!(!agents_fns.contains(bad), "{bad}");
        }
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
        v[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
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
        // A static aarch64 (EM_AARCH64 = 183) binary, and a 32-bit one.
        let mut arm = elf(false);
        arm[18..20].copy_from_slice(&183u16.to_le_bytes());
        fs::write(&p, arm).unwrap();
        let err = is_static_elf(&p).unwrap_err();
        assert!(err.contains("not an x86-64 ELF"), "{err}");
        let mut c32 = elf(false);
        c32[4] = 1;
        fs::write(&p, c32).unwrap();
        let err = is_static_elf(&p).unwrap_err();
        assert!(err.contains("not an x86-64 ELF"), "{err}");
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
