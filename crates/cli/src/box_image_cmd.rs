//! `saiife box image build` (plan 36): bakes a base image in a one-off VM.
//! Runs as the user: verifies every input against its pin, drives passt and
//! Cloud Hypervisor as its own children, and leaves `<out>/base-<sha>.raw`
//! with its manifest. Linux only. Exit 1 when the build fails.

use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum ImageAction {
    /// Build a base image locally (needs /dev/kvm, passt, qemu-img, mtools, curl, gpgv).
    Build {
        /// The recipe (default: the one built into saiife).
        #[arg(long)]
        recipe: Option<PathBuf>,
        /// Where the image goes (default: ~/.cache/saiife/box-image/out).
        #[arg(long)]
        out: Option<PathBuf>,
        /// The static saiife binary to put in the image (default: this one).
        #[arg(long)]
        saiife_bin: Option<PathBuf>,
        /// Also keep the image's kernel for direct kernel boot.
        #[arg(long)]
        direct_kernel: bool,
    },
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Fail {
    /// The build failed or was refused: exit 1.
    Failed(String),
    /// Not on this OS: exit 5.
    Unavailable(String),
}

#[cfg(not(target_os = "linux"))]
#[cfg_attr(not(unix), allow(dead_code))]
pub fn run(_config: Option<&std::path::Path>, _action: ImageAction) -> Result<(), Fail> {
    Err(Fail::Unavailable(
        "saiife box image build runs on Linux only".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub fn run(config: Option<&std::path::Path>, action: ImageAction) -> Result<(), Fail> {
    imp::run(config, action)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Fail, ImageAction};
    use crate::broker;
    use crate::text::sanitize;
    use saiife_boxhost::bake::{self, BakeInputs};
    use saiife_boxhost::image::{
        self, ubuntu, Manifest, ManifestBoot, ManifestPackage, ManifestPin, ManifestUbuntu,
        ManifestVmm, Recipe,
    };
    use saiife_boxhost::layout::Layout;
    use saiife_boxhost::pins;
    use saiife_boxhost::tools::{Tool, Tools};
    use sha2::Digest;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const BAKE_TIMEOUT: Duration = Duration::from_secs(1800);
    const PASST_WAIT: Duration = Duration::from_secs(10);
    const QEMU_IMG_TIMEOUT: Duration = Duration::from_secs(600);
    const MIN_FREE_BYTES: u64 = 20 << 30;
    const MAX_ACTUAL_BYTES: u64 = 5 << 30;
    const BASE_VIRTUAL_GIB: u64 = 10;
    const SOCK_MAX: usize = 100;
    const KERNEL_CMDLINE: &str = "console=ttyS0 root=LABEL=cloudimg-rootfs rw quiet";
    const KEYRING: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/box/ubuntu-cloudimage-keyring.gpg"
    );
    const GUEST_ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/box/guest");
    const STATIC_HINT: &str = "build saiife for x86_64-unknown-linux-musl, or pass --saiife-bin";
    const VMM_HINT: &str = "run `saiife box vmm fetch`";
    /// The tools a bake runs, checked before anything starts.
    const NEEDED: [Tool; 7] = [
        Tool::Ch,
        Tool::QemuImg,
        Tool::Gpgv,
        Tool::Curl,
        Tool::Passt,
        Tool::MkfsVfat,
        Tool::Mcopy,
    ];

    /// A debug-only test seam; release builds never read it.
    fn test_env(k: &str) -> Option<OsString> {
        if !cfg!(debug_assertions) {
            return None;
        }
        std::env::var_os(k).filter(|v| !v.is_empty())
    }

    fn abs_env(k: &str) -> Option<PathBuf> {
        std::env::var_os(k)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }

    /// Everything the build needs, resolved by the command.
    pub struct Build {
        pub recipe_text: String,
        pub out: PathBuf,
        /// Downloads: the Ubuntu image, its checksums, the Claude binary.
        pub cache: PathBuf,
        pub saiife_bin: PathBuf,
        pub direct_kernel: bool,
        pub vmm: PathBuf,
        pub keyring: PathBuf,
        pub guest_assets: PathBuf,
        /// `/dev/kvm`, or the debug seam's file.
        pub kvm: PathBuf,
        /// The debug seam's free-space reading.
        pub free_bytes: Option<u64>,
        pub bake_timeout: Duration,
        /// False when the CH tool is overridden (debug builds only).
        pub verify_vmm: bool,
        /// UTC, for `work-<stamp>` and `logs-<stamp>`.
        pub stamp: String,
        /// RFC 3339 UTC.
        pub built_at: String,
    }

    #[derive(Debug)]
    pub struct Built {
        pub id: String,
        pub raw: PathBuf,
        pub manifest: PathBuf,
    }

    pub(super) fn run(config: Option<&Path>, action: ImageAction) -> Result<(), Fail> {
        let ImageAction::Build {
            recipe,
            out,
            saiife_bin,
            direct_kernel,
        } = action;
        let failed = Fail::Failed;
        let home = abs_env("HOME");
        let cache_home = abs_env("XDG_CACHE_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".cache")))
            .ok_or_else(|| failed("cannot find your cache dir (HOME is not set)".into()))?;
        let cache = cache_home.join("saiife").join("box-image");
        let out = out.unwrap_or_else(|| cache.join("out"));
        let locked = broker::resolve_here(config)
            .map_err(Fail::Unavailable)?
            .is_locked();
        let vmm = if locked {
            Layout::locked().vmm
        } else {
            let data_home = abs_env("XDG_DATA_HOME")
                .or_else(|| home.as_ref().map(|h| h.join(".local/share")))
                .ok_or_else(|| failed("cannot find your data dir (HOME is not set)".into()))?;
            Layout::personal(&data_home, &data_home).vmm
        };
        let recipe_text = match &recipe {
            Some(p) => fs::read_to_string(p)
                .map_err(|e| failed(format!("cannot read the recipe {}: {e}", p.display())))?,
            None => image::DEFAULT_RECIPE.to_string(),
        };
        let saiife_bin = match saiife_bin {
            Some(p) => p,
            None => std::env::current_exe()
                .map_err(|e| failed(format!("cannot find this saiife binary: {e}")))?,
        };
        let path_seam = |k: &str, default: &str| -> PathBuf {
            let p = test_env(k).map_or_else(|| PathBuf::from(default), PathBuf::from);
            // gpgv reads a keyring name without a slash from GNUPG home:
            // always hand over an absolute path.
            fs::canonicalize(&p).unwrap_or(p)
        };
        let keyring = path_seam("SAIIFE_TEST_KEYRING", KEYRING);
        let guest_assets = path_seam("SAIIFE_TEST_GUEST_ASSETS", GUEST_ASSETS);
        let kvm =
            test_env("SAIIFE_TEST_KVM").map_or_else(|| PathBuf::from("/dev/kvm"), PathBuf::from);
        let free_bytes = test_env("SAIIFE_TEST_FREE_BYTES")
            .and_then(|v| v.to_str().and_then(|s| s.parse().ok()));
        let bake_timeout = test_env("SAIIFE_TEST_BAKE_TIMEOUT")
            .and_then(|v| v.to_str().and_then(|s| s.parse().ok()))
            .map_or(BAKE_TIMEOUT, Duration::from_secs);
        let verify_vmm = test_env("SAIIFE_TOOL_CH").is_none();
        let tools = Tools::system(&vmm).with_env(&|k| std::env::var_os(k));
        let now = time::OffsetDateTime::now_utc();
        let now = now.replace_nanosecond(0).unwrap_or(now);
        let stamp = now
            .format(time::macros::format_description!(
                "[year][month][day]T[hour][minute][second]Z"
            ))
            .map_err(|e| failed(e.to_string()))?;
        let built_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| failed(e.to_string()))?;
        let b = Build {
            recipe_text,
            out,
            cache,
            saiife_bin,
            direct_kernel,
            vmm,
            keyring,
            guest_assets,
            kvm,
            free_bytes,
            bake_timeout,
            verify_vmm,
            stamp,
            built_at,
        };
        let actual_size: fn(&Path) -> io::Result<u64> =
            if test_env("SAIIFE_TEST_BASE_ACTUAL_BYTES").is_some() {
                seam_actual_size
            } else {
                actual_size
            };
        let done = build(&tools, &b, actual_size).map_err(failed)?;
        let raw = sanitize(&done.raw.display().to_string());
        outln!("image {}", sanitize(&done.id));
        outln!("  {raw}");
        outln!("  {}", sanitize(&done.manifest.display().to_string()));
        outln!("next: saiife box image import {raw}");
        Ok(())
    }

    /// The space a file takes on disk: `st_blocks * 512`.
    fn actual_size(p: &Path) -> io::Result<u64> {
        Ok(fs::metadata(p)?.blocks().saturating_mul(512))
    }

    /// `SAIIFE_TEST_BASE_ACTUAL_BYTES` (debug builds only).
    fn seam_actual_size(_p: &Path) -> io::Result<u64> {
        test_env("SAIIFE_TEST_BASE_ACTUAL_BYTES")
            .and_then(|v| v.to_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| io::Error::other("SAIIFE_TEST_BASE_ACTUAL_BYTES is not a number"))
    }

    fn work_dir(b: &Build, out: &Path) -> PathBuf {
        out.join(format!("work-{}", b.stamp))
    }

    fn fw(b: &Build) -> PathBuf {
        b.vmm.join("CLOUDHV.fd")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Bakes the image. On a failure after the work dir exists, the
    /// partial image is removed and the logs are kept in `<out>/logs-<ts>`.
    pub fn build(
        tools: &Tools,
        b: &Build,
        actual_size: fn(&Path) -> io::Result<u64>,
    ) -> Result<Built, String> {
        let out = preflight(tools, b)?;
        let recipe = load_recipe(b)?;
        check_saiife_bin(&b.saiife_bin)?;
        check_vmm(b)?;
        let ubuntu_img = ubuntu::fetch_verified(tools, &b.cache, &recipe, &b.keyring)?;
        let claude_bin = b.cache.join(format!("claude-{}", recipe.claude.sha256));
        pins::fetch(
            tools,
            &recipe.claude.url,
            &recipe.claude.sha256,
            &claude_bin,
            0o755,
        )?;
        let work = work_dir(b, &out);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .map_err(|e| format!("cannot create {}: {e}", work.display()))?;
        let base_tmp = out.join("base.tmp");
        let kernel_tmp = out.join("base.vmlinuz.tmp");
        let r = bake_in(
            tools,
            b,
            &out,
            &work,
            &recipe,
            &ubuntu_img,
            &claude_bin,
            &base_tmp,
            &kernel_tmp,
            actual_size,
        );
        let r = r.map_err(|e| {
            let _ = fs::remove_file(&base_tmp);
            let _ = fs::remove_file(&kernel_tmp);
            match keep_logs(&out, &work, &b.stamp) {
                Some(logs) => format!("{e}; the logs are in {}", logs.display()),
                None => e,
            }
        });
        let _ = fs::remove_dir_all(&work);
        r
    }

    /// Paths, tools, /dev/kvm and free space. Returns the absolute `out`.
    fn preflight(tools: &Tools, b: &Build) -> Result<PathBuf, String> {
        let unsafe_path = |p: &Path| p.to_string_lossy().contains([',', '=']);
        for p in [&b.out, &b.vmm] {
            if unsafe_path(p) {
                return Err(format!(
                    "{} has a ',' or '=', which Cloud Hypervisor cannot take; pick another --out",
                    p.display()
                ));
            }
        }
        let missing: Vec<String> = NEEDED
            .iter()
            .map(|t| tools.path(*t))
            .filter(|p| !p.is_file())
            .map(|p| p.display().to_string())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "the bake needs these tools, which are missing: {}",
                missing.join(", ")
            ));
        }
        rustix::fs::access(
            &b.kvm,
            rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
        )
        .map_err(|e| {
            format!(
                "the bake needs read-write access to {} ({e}); add yourself to the kvm group",
                b.kvm.display()
            )
        })?;
        fs::create_dir_all(&b.out)
            .map_err(|e| format!("cannot create {}: {e}", b.out.display()))?;
        let out = fs::canonicalize(&b.out).map_err(|e| format!("{}: {e}", b.out.display()))?;
        if unsafe_path(&out) {
            return Err(format!(
                "{} has a ',' or '=', which Cloud Hypervisor cannot take; pick another --out",
                out.display()
            ));
        }
        let sock = work_dir(b, &out).join("passt.sock");
        if sock.as_os_str().len() > SOCK_MAX {
            return Err(format!(
                "{} is longer than {SOCK_MAX} bytes; pick a shorter --out",
                sock.display()
            ));
        }
        let free = match b.free_bytes {
            Some(n) => n,
            None => {
                let st =
                    rustix::fs::statvfs(&out).map_err(|e| format!("{}: {e}", out.display()))?;
                st.f_bavail.saturating_mul(st.f_frsize)
            }
        };
        if free < MIN_FREE_BYTES {
            return Err(format!(
                "the bake needs 20 GiB free in {}, there are {} MiB",
                out.display(),
                free >> 20
            ));
        }
        Ok(out)
    }

    fn load_recipe(b: &Build) -> Result<Recipe, String> {
        let mut r = image::parse_recipe(&b.recipe_text)?;
        r.direct_kernel |= b.direct_kernel;
        Ok(r)
    }

    fn check_saiife_bin(p: &Path) -> Result<(), String> {
        match bake::is_static_elf(p) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!(
                "{} is linked dynamically; {STATIC_HINT}",
                p.display()
            )),
            Err(e) => Err(format!("{e}; {STATIC_HINT}")),
        }
    }

    fn check_vmm(b: &Build) -> Result<(), String> {
        if !b.verify_vmm {
            return Ok(());
        }
        for (p, want) in [
            (b.vmm.join("cloud-hypervisor"), pins::CH_SHA256),
            (fw(b), pins::FW_SHA256),
        ] {
            if !p.is_file() {
                return Err(format!("{} is missing; {VMM_HINT}", p.display()));
            }
            pins::verify(&p, want).map_err(|e| format!("{e}; {VMM_HINT}"))?;
        }
        Ok(())
    }

    fn qemu_img(tools: &Tools, args: &[&OsStr]) -> Result<(), String> {
        tools
            .run(Tool::QemuImg, args, QEMU_IMG_TIMEOUT)
            .map(|_| ())
            .map_err(|e| format!("qemu-img: {e:?}"))
    }

    #[allow(clippy::too_many_arguments)]
    fn bake_in(
        tools: &Tools,
        b: &Build,
        out: &Path,
        work: &Path,
        recipe: &Recipe,
        ubuntu_img: &Path,
        claude_bin: &Path,
        base_tmp: &Path,
        kernel_tmp: &Path,
        actual_size: fn(&Path) -> io::Result<u64>,
    ) -> Result<Built, String> {
        let _ = fs::remove_file(base_tmp);
        let _ = fs::remove_file(kernel_tmp);
        qemu_img(
            tools,
            &[
                "convert".as_ref(),
                "-f".as_ref(),
                "qcow2".as_ref(),
                "-O".as_ref(),
                "raw".as_ref(),
                ubuntu_img.as_os_str(),
                base_tmp.as_os_str(),
            ],
        )?;
        let size = format!("{BASE_VIRTUAL_GIB}G");
        qemu_img(
            tools,
            &[
                "resize".as_ref(),
                "-f".as_ref(),
                "raw".as_ref(),
                base_tmp.as_os_str(),
                size.as_ref(),
            ],
        )?;
        let seed = work.join("seed.img");
        let payload = work.join("payload.img");
        let user_data = bake::render_user_data(bake::USER_DATA_TMPL, bake::BAKE_SCRIPT);
        bake::make_seed(tools, &seed, &user_data)?;
        let inputs = BakeInputs {
            saiife_bin: b.saiife_bin.clone(),
            claude_bin: claude_bin.to_path_buf(),
            guest_assets: b.guest_assets.clone(),
            recipe: recipe.clone(),
        };
        bake::make_payload(tools, &payload, &inputs)?;

        run_vm(tools, b, work, base_tmp, &seed, &payload)?;

        let serial = fs::read_to_string(work.join("serial.log")).unwrap_or_default();
        if !bake::bake_check(&serial) {
            return Err(
                "the bake did not finish: no SAIIFE-BAKE-OK line on the serial console".into(),
            );
        }
        let pk = work.join("packages.txt");
        bake::read_out(tools, &payload, "packages.txt", &pk)?;
        let packages =
            parse_packages(&fs::read_to_string(&pk).map_err(|e| format!("packages.txt: {e}"))?)?;
        if recipe.direct_kernel {
            bake::read_out(tools, &payload, "vmlinuz", kernel_tmp)?;
        }

        fs::set_permissions(base_tmp, fs::Permissions::from_mode(0o444))
            .map_err(|e| format!("{}: {e}", base_tmp.display()))?;
        let sha =
            pins::sha256_file(base_tmp).map_err(|e| format!("{}: {e}", base_tmp.display()))?;
        let actual = actual_size(base_tmp).map_err(|e| format!("{}: {e}", base_tmp.display()))?;
        if actual > MAX_ACTUAL_BYTES {
            return Err(format!(
                "the base image takes {actual} bytes on disk, more than 5 GiB"
            ));
        }
        let id = image::image_id(&sha);
        let boot = if recipe.direct_kernel {
            ManifestBoot::Kernel {
                kernel: format!("{id}.vmlinuz"),
                cmdline: KERNEL_CMDLINE.into(),
            }
        } else {
            ManifestBoot::Firmware
        };
        let saiife_sha = pins::sha256_file(&b.saiife_bin)
            .map_err(|e| format!("{}: {e}", b.saiife_bin.display()))?;
        let m = Manifest {
            version: 1,
            id: id.clone(),
            sha256: sha,
            virtual_gib: BASE_VIRTUAL_GIB,
            actual_bytes: actual,
            built_at: b.built_at.clone(),
            builder: format!("saiife {}", env!("CARGO_PKG_VERSION")),
            recipe_sha256: hex(&sha2::Sha256::digest(b.recipe_text.as_bytes())),
            ubuntu: ManifestUbuntu {
                release: recipe.ubuntu_release.clone(),
                image_sha256: recipe.ubuntu_sha256.clone(),
                sums_signer: ubuntu::UBUNTU_CLOUD_FPR.into(),
            },
            vmm: ManifestVmm {
                ch_version: pins::CH_VERSION.into(),
                ch_sha256: pins::CH_SHA256.into(),
                fw_version: pins::FW_VERSION.into(),
                fw_sha256: pins::FW_SHA256.into(),
            },
            saiife: ManifestPin {
                version: env!("CARGO_PKG_VERSION").into(),
                sha256: saiife_sha,
            },
            claude: ManifestPin {
                version: recipe.claude.version.clone(),
                sha256: recipe.claude.sha256.clone(),
            },
            packages,
            images: recipe.images.clone(),
            boot,
            signature: None,
        };
        let json = m.to_json();
        Manifest::parse(&json)?;
        let raw = out.join(format!("{id}.raw"));
        let kernel = out.join(format!("{id}.vmlinuz"));
        let manifest = out.join(format!("{id}.json"));
        let json_tmp = out.join(format!(".{id}.json.tmp"));
        let placed = (|| -> Result<(), String> {
            let e = |p: &Path, x: io::Error| format!("{}: {x}", p.display());
            fs::rename(base_tmp, &raw).map_err(|x| e(&raw, x))?;
            if recipe.direct_kernel {
                fs::rename(kernel_tmp, &kernel).map_err(|x| e(&kernel, x))?;
            }
            fs::write(&json_tmp, json).map_err(|x| e(&json_tmp, x))?;
            fs::rename(&json_tmp, &manifest).map_err(|x| e(&manifest, x))
        })();
        if let Err(err) = placed {
            for p in [&raw, &kernel, &json_tmp, &manifest] {
                let _ = fs::remove_file(p);
            }
            return Err(err);
        }
        Ok(Built { id, raw, manifest })
    }

    /// `dpkg-query -W -f '${Package} ${Version}\n'` output.
    fn parse_packages(text: &str) -> Result<Vec<ManifestPackage>, String> {
        let mut v = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let ok =
                |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control());
            match line.split_once(' ') {
                Some((name, version)) if ok(name) && ok(version) => v.push(ManifestPackage {
                    name: name.into(),
                    version: version.into(),
                }),
                _ => return Err(format!("packages.txt: bad line {line:?}")),
            }
        }
        if v.is_empty() {
            return Err("the bake wrote an empty packages.txt".into());
        }
        Ok(v)
    }

    /// Our own passt and CH children; both are killed and reaped on drop.
    struct Kids {
        passt: Option<Child>,
        ch: Option<Child>,
    }

    fn stop(c: &mut Option<Child>) {
        if let Some(mut c) = c.take() {
            if !matches!(c.try_wait(), Ok(Some(_))) {
                let _ = c.kill();
            }
            let _ = c.wait();
        }
    }

    impl Drop for Kids {
        fn drop(&mut self) {
            stop(&mut self.ch);
            stop(&mut self.passt);
        }
    }

    fn spawn(path: &Path, args: &[OsString], log: &Path) -> Result<Child, String> {
        let f = File::create(log).map_err(|e| format!("{}: {e}", log.display()))?;
        let f2 = f
            .try_clone()
            .map_err(|e| format!("{}: {e}", log.display()))?;
        Command::new(path)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(f)
            .stderr(f2)
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", path.display()))
    }

    /// passt, then the bake VM; waits for the VM to power off.
    fn run_vm(
        tools: &Tools,
        b: &Build,
        work: &Path,
        base: &Path,
        seed: &Path,
        payload: &Path,
    ) -> Result<(), String> {
        let sock = work.join("passt.sock");
        let mut kids = Kids {
            passt: None,
            ch: None,
        };
        let passt_args: Vec<OsString> = vec![
            "-f".into(),
            "--vhost-user".into(),
            "--one-off".into(),
            "--socket-path".into(),
            sock.clone().into(),
        ];
        kids.passt = Some(spawn(
            tools.path(Tool::Passt),
            &passt_args,
            &work.join("passt.log"),
        )?);
        let deadline = Instant::now() + PASST_WAIT;
        while !sock.exists() {
            if let Some(p) = kids.passt.as_mut() {
                if let Ok(Some(st)) = p.try_wait() {
                    return Err(format!("passt exited ({st}) before it made its socket"));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "passt made no socket within {} s",
                    PASST_WAIT.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let argv = bake::bake_argv(base, seed, payload, &fw(b), work);
        kids.ch = Some(spawn(tools.path(Tool::Ch), &argv, &work.join("ch.log"))?);
        let deadline = Instant::now() + b.bake_timeout;
        let status = loop {
            let ch = kids.ch.as_mut().expect("started above");
            match ch.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) if Instant::now() >= deadline => {
                    return Err(format!(
                        "the bake VM did not finish within {} s; it was stopped",
                        b.bake_timeout.as_secs()
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(format!("cloud-hypervisor: {e}")),
            }
        };
        kids.ch = None;
        stop(&mut kids.passt);
        if !status.success() {
            return Err(format!("cloud-hypervisor exited with {status}"));
        }
        Ok(())
    }

    /// Copies the bake's logs to `<out>/logs-<stamp>/`.
    fn keep_logs(out: &Path, work: &Path, stamp: &str) -> Option<PathBuf> {
        let names = ["serial.log", "ch.log", "passt.log"];
        if !names.iter().any(|n| work.join(n).is_file()) {
            return None;
        }
        let logs = out.join(format!("logs-{stamp}"));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&logs)
            .ok()?;
        for n in names {
            let _ = fs::copy(work.join(n), logs.join(n));
        }
        Some(logs)
    }
}
