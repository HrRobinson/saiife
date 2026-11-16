//! `saiife box image build` (plan 36, Task 4) against fake host tools. Every
//! tool is a shell script in a tempdir named through the debug-only
//! `SAIIFE_TOOL_*` seams; nothing here boots a VM, downloads or touches
//! /dev/kvm. The fake passt (and the hanging fake CH) block on a builtin
//! `read` from a fifo they hold open, so only `Child::kill` ends them; the
//! test reads that fifo to EOF to see that both were killed.
#![cfg(target_os = "linux")]

use saiife_boxhost::image::ubuntu::{UBUNTU_CLOUD_FPR, UBUNTU_IMAGE};
use saiife_boxhost::image::{Manifest, ManifestBoot, ManifestPackage};
use saiife_boxhost::pins::{self, sha256_file};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const GOOD_STATUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../boxhost/tests/fixtures/gpgv/good.status"
);
const IMAGE: &str = "fake-qcow2-image\n";
const CLAUDE: &str = "fake-claude-binary\n";
const PACKAGES: &str = "socat 1.8.0\ngit 1:2.43.0\n";

/// What the fake Cloud Hypervisor (and passt) do.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ch {
    /// Writes the marker to the serial file and exits 0.
    Ok,
    /// Like `Ok`, with bytes that are not UTF-8 on the serial console.
    Binary,
    /// passt blocks without ever making its socket.
    PasstNoSocket,
    /// passt exits 3 without making its socket.
    PasstExits,
    /// Exits 0 with only the `set -x` trace of the marker.
    NoMarker,
    /// Blocks until killed.
    Hang,
}

struct W {
    d: tempfile::TempDir,
    img_sha: String,
    claude_sha: String,
    saiife_bin: PathBuf,
    recipe: PathBuf,
    alive: mpsc::Receiver<()>,
}

fn exec(p: &Path, body: &str) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// An ELF64 LE header; with `interp`, one PT_INTERP program header.
fn elf(interp: bool) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    h[18..20].copy_from_slice(&62u16.to_le_bytes());
    if interp {
        h[32..40].copy_from_slice(&64u64.to_le_bytes());
        h[54..56].copy_from_slice(&56u16.to_le_bytes());
        h[56..58].copy_from_slice(&1u16.to_le_bytes());
        let mut ph = vec![0u8; 56];
        ph[..4].copy_from_slice(&3u32.to_le_bytes());
        h.extend(ph);
    }
    h
}

fn recipe_text(img_sha: &str, claude_sha: &str) -> String {
    format!(
        "[ubuntu]\nrelease = \"release-20261017\"\nsha256 = \"{img_sha}\"\n[packages]\napt = [\"socat\", \"git\"]\n[images]\npull = []\n[claude]\nversion = \"0.0.0-test\"\nurl = \"https://example.invalid/claude\"\nsha256 = \"{claude_sha}\"\n[boot]\ndirect_kernel = false\n"
    )
}

fn world(ch: Ch) -> W {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    let t = p.join("t");
    let serve = p.join("serve");
    for dir in [&t, &serve, &p.join("h")] {
        std::fs::create_dir(dir).unwrap();
    }
    let log = p.join("calls.log");
    let alive = p.join("alive.fifo");
    let st = Command::new("/usr/bin/mkfifo")
        .arg(&alive)
        .status()
        .unwrap();
    assert!(st.success());

    std::fs::write(serve.join(UBUNTU_IMAGE), IMAGE).unwrap();
    std::fs::write(serve.join("claude"), CLAUDE).unwrap();
    let img_sha = sha256_file(&serve.join(UBUNTU_IMAGE)).unwrap();
    let claude_sha = sha256_file(&serve.join("claude")).unwrap();
    std::fs::write(
        serve.join("SHA256SUMS"),
        format!("{img_sha} *{UBUNTU_IMAGE}\n"),
    )
    .unwrap();
    std::fs::write(serve.join("SHA256SUMS.gpg"), "sig").unwrap();

    let (l, a, s) = (log.display(), alive.display(), serve.display());
    exec(
        &t.join("curl"),
        &format!(
            "#!/bin/sh\nfor a; do last=$a; done\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -o ]; then out=$2; fi\n  shift\ndone\necho \"curl $last\" >>'{l}'\ncp \"{s}/${{last##*/}}\" \"$out\"\n"
        ),
    );
    exec(
        &t.join("gpgv"),
        &format!("#!/bin/sh\ncat '{GOOD_STATUS}'\n"),
    );
    exec(
        &t.join("qemu-img"),
        &format!(
            "#!/bin/sh\necho \"qemu-img $*\" >>'{l}'\nif [ \"$1\" = convert ]; then\n  for a; do prev=$last; last=$a; done\n  cp \"$prev\" \"$last\"\nfi\n"
        ),
    );
    exec(
        &t.join("mkfs.vfat"),
        &format!("#!/bin/sh\necho \"mkfs.vfat $*\" >>'{l}'\n"),
    );
    exec(
        &t.join("mcopy"),
        &format!(
            "#!/bin/sh\nfor a; do last=$a; done\ncase \" $* \" in\n  *' ::out/packages.txt '*) printf '{}' >\"$last\" ;;\n  *' ::out/vmlinuz '*) printf 'kernel' >\"$last\" ;;\n  *) echo \"mcopy $*\" >>'{l}' ;;\nesac\n",
            PACKAGES.replace('\n', "\\n")
        ),
    );
    let make_sock = match ch {
        Ch::PasstNoSocket => "",
        Ch::PasstExits => "echo 'passt: no' >&2\nexit 3\n",
        _ => ": >\"$sock\"\n",
    };
    exec(
        &t.join("passt"),
        &format!(
            "#!/bin/sh\necho \"passt $*\" >>'{l}'\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = --socket-path ]; then sock=$2; fi\n  shift\ndone\nexec 3<>'{a}'\n{make_sock}read -r x <&3\n"
        ),
    );
    let serial = "prev=\nfor a; do\n  if [ \"$prev\" = --serial ]; then serial=${a#file=}; fi\n  prev=$a\ndone\n";
    let tail = match ch {
        Ch::Binary => {
            "printf 'boot\\377\\376\\300\\r\\nSAIIFE-BAKE-OK\\r\\n\\377' >\"$serial\"\n".to_string()
        }
        Ch::Ok | Ch::PasstNoSocket | Ch::PasstExits => {
            "printf 'booting\\r\\nSAIIFE-BAKE-OK\\r\\n' >\"$serial\"\necho 'ch says hi'\n"
                .to_string()
        }
        Ch::NoMarker => {
            "printf '+ echo SAIIFE-BAKE-OK\\nboom\\n' >\"$serial\"\necho 'ch failed'\n".to_string()
        }
        Ch::Hang => format!("printf 'booting\\n' >\"$serial\"\nexec 3<>'{a}'\nread -r x <&3\n"),
    };
    exec(
        &t.join("ch"),
        &format!("#!/bin/sh\necho \"ch $*\" >>'{l}'\n{serial}{tail}"),
    );

    let saiife_bin = p.join("saiife-static");
    std::fs::write(&saiife_bin, elf(false)).unwrap();
    std::fs::write(p.join("saiife-dynamic"), elf(true)).unwrap();
    std::fs::write(p.join("keyring.gpg"), "k").unwrap();
    std::fs::write(p.join("kvm"), "").unwrap();
    let recipe = p.join("recipe.toml");
    std::fs::write(&recipe, recipe_text(&img_sha, &claude_sha)).unwrap();

    // EOF on the fifo means every fake that held it open is gone.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut f = std::fs::File::open(&alive).unwrap();
        let mut v = Vec::new();
        let _ = f.read_to_end(&mut v);
        let _ = tx.send(());
    });
    W {
        d,
        img_sha,
        claude_sha,
        saiife_bin,
        recipe,
        alive: rx,
    }
}

impl W {
    fn p(&self) -> &Path {
        self.d.path()
    }

    fn build(&self, extra: &[&str], env: &[(&str, &str)]) -> Output {
        self.build_to(self.p(), extra, env)
    }

    fn build_to(&self, out: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
        let p = self.p();
        let t = p.join("t");
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
        c.args(["box", "image", "build", "--out"])
            .arg(out)
            .args(extra)
            .env_clear()
            .env("HOME", p.join("h"))
            .env("XDG_CACHE_HOME", p.join("cache"))
            .env("XDG_DATA_HOME", p.join("data"))
            .env("XDG_STATE_HOME", p.join("state"))
            .env("XDG_CONFIG_HOME", p.join("config"))
            .env("XDG_RUNTIME_DIR", p.join("no-runtime"))
            .env("SAIIFE_DATA_DIR", p.join("sdata"))
            .env("SAIIFE_AUDIT_DIR", p.join("audit"))
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/dead")
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_TEST_SYSTEM_CONFIG", p.join("no-system.toml"))
            .env("SAIIFE_TEST_KEYRING", p.join("keyring.gpg"))
            .env("SAIIFE_TEST_KVM", p.join("kvm"))
            .env("SAIIFE_TEST_FREE_BYTES", (100u64 << 30).to_string())
            .stdin(Stdio::null());
        for (var, name) in [
            ("SAIIFE_TOOL_CH", "ch"),
            ("SAIIFE_TOOL_QEMU_IMG", "qemu-img"),
            ("SAIIFE_TOOL_GPGV", "gpgv"),
            ("SAIIFE_TOOL_CURL", "curl"),
            ("SAIIFE_TOOL_PASST", "passt"),
            ("SAIIFE_TOOL_MKFS_VFAT", "mkfs.vfat"),
            ("SAIIFE_TOOL_MCOPY", "mcopy"),
        ] {
            c.env(var, t.join(name));
        }
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn pinned(&self, env: &[(&str, &str)]) -> Output {
        let r = self.recipe.display().to_string();
        let s = self.saiife_bin.display().to_string();
        self.build(&["--recipe", &r, "--saiife-bin", &s], env)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.p().join("calls.log")).unwrap_or_default()
    }

    fn names(&self, prefix: &str) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(self.p())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
            .collect();
        v.sort();
        v
    }

    /// No image, no temp file and no work dir were left in `out`.
    fn assert_no_image(&self) {
        assert!(self.names("base").is_empty(), "{:?}", self.names("base"));
        assert!(self.names("work-").is_empty(), "{:?}", self.names("work-"));
    }

    fn assert_children_gone(&self) {
        self.alive
            .recv_timeout(Duration::from_secs(10))
            .expect("the fake passt or CH is still alive");
    }
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn build_produces_image_and_manifest() {
    let w = world(Ch::Ok);
    let o = w.pinned(&[]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}\n{err}\n{}", w.log());
    w.assert_children_gone();

    let raws = w.names("base-");
    assert_eq!(raws.len(), 2, "{raws:?}");
    let json = raws
        .iter()
        .find(|p| p.extension().unwrap() == "json")
        .unwrap();
    let raw = raws
        .iter()
        .find(|p| p.extension().unwrap() == "raw")
        .unwrap();
    let m = Manifest::parse(&std::fs::read_to_string(json).unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(raw).unwrap(), IMAGE);
    let mode = std::fs::metadata(raw).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o444);
    assert_eq!(m.sha256, sha256_file(raw).unwrap());
    assert_eq!(
        raw.file_name().unwrap().to_string_lossy(),
        format!("{}.raw", m.id)
    );
    assert_eq!(m.virtual_gib, 10);
    assert!(m.builder.starts_with("saiife "), "{}", m.builder);
    assert!(
        m.built_at.ends_with('Z') && m.built_at.contains('T'),
        "{}",
        m.built_at
    );
    assert_eq!(m.recipe_sha256, sha256_file(&w.recipe).unwrap());
    assert_eq!(m.ubuntu.release, "release-20261017");
    assert_eq!(m.ubuntu.image_sha256, w.img_sha);
    assert_eq!(m.ubuntu.sums_signer, UBUNTU_CLOUD_FPR);
    assert_eq!(m.vmm.ch_version, pins::CH_VERSION);
    assert_eq!(m.vmm.ch_sha256, pins::CH_SHA256);
    assert_eq!(m.vmm.fw_version, pins::FW_VERSION);
    assert_eq!(m.vmm.fw_sha256, pins::FW_SHA256);
    assert_eq!(m.saiife.sha256, sha256_file(&w.saiife_bin).unwrap());
    assert_eq!(m.claude.version, "0.0.0-test");
    assert_eq!(m.claude.sha256, w.claude_sha);
    let pkg = |n: &str, v: &str| ManifestPackage {
        name: n.into(),
        version: v.into(),
    };
    assert_eq!(
        m.packages,
        vec![pkg("socat", "1.8.0"), pkg("git", "1:2.43.0")]
    );
    assert!(m.images.is_empty());
    assert_eq!(m.boot, ManifestBoot::Firmware);
    assert_eq!(m.signature, None);

    assert!(out.contains(&m.id), "{out}");
    assert!(out.contains("saiife box image import"), "{out}");
    assert!(w.names("work-").is_empty() && w.names("logs-").is_empty());

    let log = w.log();
    assert!(log.contains("qemu-img convert"), "{log}");
    assert!(log.contains("qemu-img resize -f raw"), "{log}");
    assert!(log.contains(" 10G"), "{log}");
    assert!(
        log.contains("passt -f --vhost-user --one-off --socket-path "),
        "{log}"
    );
    assert!(log.contains("size=4096M,shared=on"), "{log}");
    assert!(log.contains("vhost_user=true,socket="), "{log}");
    assert!(log.contains("curl https://example.invalid/claude"), "{log}");
}

#[test]
fn build_refuses_dynamic_saiife() {
    let w = world(Ch::Ok);
    let r = w.recipe.display().to_string();
    let s = w.p().join("saiife-dynamic").display().to_string();
    let o = w.build(&["--recipe", &r, "--saiife-bin", &s], &[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("x86_64-unknown-linux-musl"), "{err}");
    assert!(err.contains("--saiife-bin"), "{err}");
    assert!(!w.log().contains("ch "), "{}", w.log());
    w.assert_no_image();
}

#[test]
fn build_refuses_unpinned_claude() {
    let w = world(Ch::Ok);
    let s = w.saiife_bin.display().to_string();
    // The shipped recipe leaves Claude Code UNPINNED.
    let o = w.build(&["--saiife-bin", &s], &[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("claude.sha256 is UNPINNED"), "{err}");
    let unpinned = recipe_text(&w.img_sha, "UNPINNED");
    std::fs::write(&w.recipe, unpinned).unwrap();
    let o = w.pinned(&[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("UNPINNED"), "{err}");
    assert_eq!(w.log(), "", "nothing ran");
    w.assert_no_image();
}

#[test]
fn image_build_with_codex_unpinned_fails() {
    let w = world(Ch::Ok);
    let s = w.saiife_bin.display().to_string();
    // The shipped recipe, with only its Claude Code pin filled in: its
    // [codex] section is off and UNPINNED.
    let shipped = saiife_boxhost::image::DEFAULT_RECIPE;
    let (head, tail) = shipped.split_once("[claude]\n").unwrap();
    let rest = tail.split_once("\n[").map_or("", |(_, r)| r);
    let recipe = format!(
        "{head}[claude]\nversion = \"0.0.0-test\"\nurl = \"https://example.invalid/claude\"\nsha256 = \"{}\"\n[{rest}",
        w.claude_sha
    );
    assert!(recipe.contains("[codex]\nenabled = false\n"), "{recipe}");
    std::fs::write(&w.recipe, recipe).unwrap();
    let r = w.recipe.display().to_string();
    let o = w.build(
        &["--recipe", &r, "--saiife-bin", &s, "--with", "codex"],
        &[],
    );
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.contains(
            "codex.sha256 is UNPINNED; pin the Codex release first (or set codex.enabled = false)"
        ),
        "{err}"
    );
    assert_eq!(w.log(), "", "nothing fetched, nothing ran");
    assert!(!w.p().join("cache").exists(), "nothing fetched");
    w.assert_no_image();
    // Claude Code is always in the image: --with claude-code is refused.
    let o = w.build(
        &["--recipe", &r, "--saiife-bin", &s, "--with", "claude-code"],
        &[],
    );
    let (_, err) = text(&o);
    assert_ne!(o.status.code(), Some(0), "{err}");
    assert!(err.contains("always in the image"), "{err}");
    assert_eq!(w.log(), "", "nothing ran");
}

#[test]
fn build_with_agents_fetches_and_lists_them() {
    let w = world(Ch::Ok);
    let serve = w.p().join("serve");
    let mut shas = Vec::new();
    for (name, body) in [
        ("codex.tar.gz", "fake codex"),
        ("gemini-cli-bundle.zip", "fake gemini"),
        ("node.tar.xz", "fake node"),
    ] {
        std::fs::write(serve.join(name), body).unwrap();
        shas.push(sha256_file(&serve.join(name)).unwrap());
    }
    let mut recipe =
        recipe_text(&w.img_sha, &w.claude_sha).replace("[boot]\ndirect_kernel = false\n", "");
    recipe.push_str(&format!(
        "[codex]\nenabled = false\nversion = \"0.1.0\"\nurl = \"https://example.invalid/codex.tar.gz\"\nsha256 = \"{}\"\n[gemini]\nenabled = true\nversion = \"0.2.0\"\nurl = \"https://example.invalid/gemini-cli-bundle.zip\"\nsha256 = \"{}\"\nnode_version = \"22.0.0\"\nnode_url = \"https://example.invalid/node.tar.xz\"\nnode_sha256 = \"{}\"\n[boot]\ndirect_kernel = false\n",
        shas[0], shas[1], shas[2]
    ));
    std::fs::write(&w.recipe, recipe).unwrap();
    let r = w.recipe.display().to_string();
    let s = w.saiife_bin.display().to_string();
    let o = w.build(
        &["--recipe", &r, "--saiife-bin", &s, "--with", "codex"],
        &[],
    );
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}\n{err}\n{}", w.log());
    let json = w
        .names("base-")
        .into_iter()
        .find(|p| p.extension().unwrap() == "json")
        .unwrap();
    let m = Manifest::parse(&std::fs::read_to_string(json).unwrap()).unwrap();
    let got: Vec<(&str, &str, &str)> = m
        .agents
        .iter()
        .map(|(k, p)| (k.as_str(), p.version.as_str(), p.sha256.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("codex", "0.1.0", shas[0].as_str()),
            ("gemini", "0.2.0", shas[1].as_str()),
            ("node", "22.0.0", shas[2].as_str()),
        ]
    );
    let log = w.log();
    for n in ["codex.tar.gz", "gemini-cli-bundle.zip", "node.tar.xz"] {
        assert!(
            log.contains(&format!("curl https://example.invalid/{n}")),
            "{log}"
        );
    }
    let cache = w.p().join("cache/saiife/box-image");
    for (n, sha) in [
        ("codex", &shas[0]),
        ("gemini", &shas[1]),
        ("node", &shas[2]),
    ] {
        let f = cache.join(format!("{n}-{sha}"));
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "{n}");
    }
    // the payload carries them (the fake mcopy logs its arguments)
    for n in ["/codex.tar.gz ", "/gemini.zip ", "/node.tar.xz "] {
        assert!(log.contains(n), "{n}: {log}");
    }
}

#[test]
fn failed_bake_keeps_logs_removes_image() {
    let w = world(Ch::NoMarker);
    let o = w.pinned(&[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("SAIIFE-BAKE-OK"), "{err}");
    w.assert_children_gone();
    w.assert_no_image();
    let logs = w.names("logs-");
    assert_eq!(logs.len(), 1, "{logs:?}");
    let serial = std::fs::read_to_string(logs[0].join("serial.log")).unwrap();
    assert!(serial.contains("boom"), "{serial}");
    let ch = std::fs::read_to_string(logs[0].join("ch.log")).unwrap();
    assert!(ch.contains("ch failed"), "{ch}");
    assert!(logs[0].join("passt.log").is_file());
    assert!(err.contains(&logs[0].display().to_string()), "{err}");
}

#[test]
fn oversized_base_is_refused() {
    let w = world(Ch::Ok);
    let big = ((5u64 << 30) + 1).to_string();
    let o = w.pinned(&[("SAIIFE_TEST_BASE_ACTUAL_BYTES", &big)]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("5 GiB"), "{err}");
    w.assert_children_gone();
    w.assert_no_image();
    assert_eq!(w.names("logs-").len(), 1);
}

#[test]
fn bake_timeout_kills_own_children() {
    let w = world(Ch::Hang);
    let start = Instant::now();
    let o = w.pinned(&[("SAIIFE_TEST_BAKE_TIMEOUT", "2")]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("2 s"), "{err}");
    assert!(start.elapsed() < Duration::from_secs(30));
    w.assert_children_gone();
    w.assert_no_image();
    assert_eq!(w.names("logs-").len(), 1);
}

#[test]
fn preflight_refuses_a_missing_tool_and_a_comma_in_out() {
    let w = world(Ch::Ok);
    let o = w.pinned(&[("SAIIFE_TOOL_PASST", "/nonexistent-p36/passt")]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("/nonexistent-p36/passt"), "{err}");
    let o = w.pinned(&[("SAIIFE_TEST_FREE_BYTES", "1024")]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("20 GiB"), "{err}");
    let bad = w.p().join("a,b");
    let r = w.recipe.display().to_string();
    let s = w.saiife_bin.display().to_string();
    let o = w.build_to(&bad, &["--recipe", &r, "--saiife-bin", &s], &[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains("','"), "{err}");
    assert_eq!(w.log(), "", "nothing ran");
}

#[test]
fn direct_kernel_keeps_the_kernel() {
    let w = world(Ch::Ok);
    let r = w.recipe.display().to_string();
    let s = w.saiife_bin.display().to_string();
    let o = w.build(
        &["--recipe", &r, "--saiife-bin", &s, "--direct-kernel"],
        &[],
    );
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}\n{err}");
    w.assert_children_gone();
    let json = w
        .names("base-")
        .into_iter()
        .find(|p| p.extension().unwrap() == "json")
        .unwrap();
    let m = Manifest::parse(&std::fs::read_to_string(json).unwrap()).unwrap();
    let k = w.p().join(format!("{}.vmlinuz", m.id));
    assert_eq!(
        m.boot,
        ManifestBoot::Kernel {
            kernel: format!("{}.vmlinuz", m.id),
            sha256: sha256_file(&k).unwrap(),
            cmdline: "console=ttyS0 root=/dev/vda1 rw quiet".into(),
        }
    );
    assert_eq!(std::fs::read_to_string(k).unwrap(), "kernel");
    assert!(w.names("base.").is_empty(), "{:?}", w.names("base."));
}

#[test]
fn serial_log_with_invalid_utf8_still_passes() {
    let w = world(Ch::Binary);
    let o = w.pinned(&[]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}\n{err}");
    w.assert_children_gone();
    assert_eq!(w.names("base-").len(), 2, "{:?}", w.names("base-"));
}

fn assert_passt_failure(ch: Ch, want: &str) {
    let w = world(ch);
    let start = Instant::now();
    let o = w.pinned(&[("SAIIFE_TEST_PASST_WAIT", "1")]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(want), "{err}");
    assert!(start.elapsed() < Duration::from_secs(20));
    w.assert_children_gone();
    w.assert_no_image();
    assert!(!w.log().contains("ch "), "CH must not start: {}", w.log());
    let logs = w.names("logs-");
    assert_eq!(logs.len(), 1, "{logs:?}");
    assert!(logs[0].join("passt.log").is_file());
    assert!(w.names(".build.lock").is_empty());
}

#[test]
fn passt_without_a_socket_fails_the_build() {
    assert_passt_failure(Ch::PasstNoSocket, "no socket within 1 s");
}

#[test]
fn passt_that_exits_fails_the_build() {
    assert_passt_failure(Ch::PasstExits, "passt exited");
}

#[test]
fn a_second_build_into_the_same_out_is_refused() {
    let w = world(Ch::Ok);
    let lock = w.p().join(".build.lock");
    // Our own pid: a build that is certainly still running.
    let live = format!("{}\n", std::process::id());
    std::fs::write(&lock, &live).unwrap();
    let o = w.pinned(&[]);
    let (_, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.contains(&lock.display().to_string()), "{err}");
    assert!(err.contains("rm "), "{err}");
    assert_eq!(w.log(), "", "nothing ran");
    assert_eq!(
        std::fs::read_to_string(&lock).unwrap(),
        live,
        "not ours to remove"
    );
    std::fs::remove_file(&lock).unwrap();
    let o = w.pinned(&[]);
    assert_eq!(o.status.code(), Some(0), "{:?}", text(&o));
    assert!(!lock.exists(), "the build removes its lock");
}

#[test]
fn a_stale_build_lock_is_removed() {
    // Above the kernel's pid_max (2^22), so no such process can exist; and
    // a lock whose content is not a pid at all.
    for content in ["4194305\n", "not-a-pid\n"] {
        let w = world(Ch::Ok);
        let lock = w.p().join(".build.lock");
        std::fs::write(&lock, content).unwrap();
        let o = w.pinned(&[]);
        let (out, err) = text(&o);
        assert_eq!(o.status.code(), Some(0), "{content}: {out}\n{err}");
        assert!(err.contains("stale"), "{content}: {err}");
        assert!(!lock.exists(), "{content}: the build removes its lock");
        assert_eq!(w.names("base-").len(), 2, "{:?}", w.names("base-"));
    }
}
