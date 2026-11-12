#![cfg(feature = "fake")]
//! `ChVmm` against `saiife-fake-ch` (plan 35, Task 5). No real VMM runs.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use saiife_boxes::template::{ImageRef, Size};
use saiife_boxes::vmm::{VmHandle, VmSpec, VmStatus, Vmm, VmmError};
use saiife_boxhost::launch::{argv, read_spec, Boot, ChildLauncher, Launcher};
use saiife_boxhost::layout::Layout;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::tools::Tools;
use saiife_boxhost::vmm::{ChVmm, ChVmmInit, ImageResolver, ResolvedImage, StopTimes, VmHooks};
use saiife_wire::source::BoxId;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixed(ResolvedImage);
impl ImageResolver for Fixed {
    fn resolve(&self, _r: &ImageRef) -> Result<ResolvedImage, String> {
        Ok(self.0.clone())
    }
}

/// Records hook calls as "<name>.before" / "<name>.off".
struct Rec {
    name: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    fail: bool,
}
impl VmHooks for Rec {
    fn before_boot(&self, _id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        // "!" marks a VMM that had started before the hook ran.
        let up = if paths.dir.join("fake-ch.argv").exists() {
            "!"
        } else {
            ""
        };
        self.log
            .lock()
            .unwrap()
            .push(format!("{}.before{up}", self.name));
        if self.fail {
            Err("bind failed".into())
        } else {
            Ok(())
        }
    }
    fn after_off(&self, _id: &BoxId) {
        self.log.lock().unwrap().push(format!("{}.off", self.name));
    }
}

struct World {
    root: PathBuf,
    layout: Layout,
    tools: Tools,
    image: ResolvedImage,
    log: Arc<Mutex<Vec<String>>>,
    vmms: Mutex<Vec<(Arc<ChVmm>, VmHandle)>>,
    launchers: Mutex<Vec<Arc<ChildLauncher>>>,
}

impl World {
    fn new() -> World {
        let base = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let root = tempfile::Builder::new()
            .prefix("w")
            .tempdir_in(base)
            .unwrap()
            .keep();
        let root = std::fs::canonicalize(root).unwrap();
        for d in ["i", "v", "t"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        std::fs::write(root.join("i/base"), b"x").unwrap();
        std::fs::write(root.join("v/CLOUDHV.fd"), b"x").unwrap();
        let qemu = root.join("t/qemu-img");
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> '{}/t/qemu-argv'; prev=$last; last=$a; done\necho qcow > \"$prev\"\n",
            root.display()
        );
        std::fs::write(&qemu, script).unwrap();
        std::fs::set_permissions(&qemu, std::fs::Permissions::from_mode(0o755)).unwrap();
        let q = qemu.clone();
        let tools = Tools::system(&root.join("v")).with_env(&move |k: &str| {
            (k == "SAIIFE_TOOL_QEMU_IMG").then(|| q.clone().into_os_string())
        });
        let layout = Layout {
            boxes: root.clone(),
            images: root.join("i"),
            vmm: root.join("v"),
            locked: false,
        };
        let image = ResolvedImage {
            id: format!("base-{HEX}"),
            raw: root.join("i/base"),
            sha256: HEX.into(),
            virtual_gib: 4,
            boot: Boot::Firmware {
                fw: root.join("v/CLOUDHV.fd"),
            },
        };
        World {
            root,
            layout,
            tools,
            image,
            log: Arc::new(Mutex::new(Vec::new())),
            vmms: Mutex::new(Vec::new()),
            launchers: Mutex::new(Vec::new()),
        }
    }

    fn launcher(&self, env: &[(&str, &str)]) -> Arc<ChildLauncher> {
        let mut l = ChildLauncher::direct(PathBuf::from(env!("CARGO_BIN_EXE_saiife-fake-ch")));
        for (k, v) in env {
            l = l.env(k, v);
        }
        let l = Arc::new(l);
        self.launchers.lock().unwrap().push(Arc::clone(&l));
        l
    }

    fn vmm_with(&self, launcher: Arc<ChildLauncher>, hooks: Vec<Arc<dyn VmHooks>>) -> Arc<ChVmm> {
        Arc::new(ChVmm::new(ChVmmInit {
            layout: self.layout.clone(),
            tools: self.tools.clone(),
            images: Arc::new(Fixed(self.image.clone())),
            launcher,
            hooks,
            landlock: true,
            stop: StopTimes {
                power_s: 1,
                shutdown_s: 1,
            },
        }))
    }

    fn hook(&self, name: &'static str, fail: bool) -> Arc<dyn VmHooks> {
        Arc::new(Rec {
            name,
            log: Arc::clone(&self.log),
            fail,
        })
    }

    fn vmm(&self, env: &[(&str, &str)]) -> (Arc<ChVmm>, Arc<ChildLauncher>) {
        let l = self.launcher(env);
        let h = self.hook("h", false);
        (self.vmm_with(Arc::clone(&l), vec![h]), l)
    }

    fn spec(&self, id: &str) -> VmSpec {
        let dir = self.root.join(id);
        if !dir.exists() {
            std::fs::create_dir(&dir).unwrap();
        }
        VmSpec {
            id: BoxId::parse(id).unwrap(),
            size: Size {
                disk_gib: 8,
                ..Size::default()
            },
            image: ImageRef::Default,
            dir,
        }
    }

    fn paths(&self, id: &str) -> BoxPaths {
        BoxPaths::new(self.root.join(id))
    }

    /// Created and remembered for the Drop guard.
    fn create(&self, v: &Arc<ChVmm>, id: &str) -> VmHandle {
        let h = v.create(&self.spec(id)).unwrap();
        self.track(v, &h);
        h
    }

    fn track(&self, v: &Arc<ChVmm>, h: &VmHandle) {
        self.vmms.lock().unwrap().push((Arc::clone(v), h.clone()));
    }

    fn events(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let all = std::mem::take(&mut *self.vmms.lock().unwrap());
        for (v, h) in &all {
            let _ = v.destroy(h);
        }
        // Safety net: destroy must have left no child running.
        let mut leaks = 0;
        for l in self.launchers.lock().unwrap().iter() {
            for (_, h) in &all {
                if l.exited(&h.id) == Some(false) {
                    leaks += 1;
                    let _ = l.force_stop(&h.id);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
        if !std::thread::panicking() {
            assert_eq!(leaks, 0, "a VMM child outlived destroy");
        }
    }
}

fn wait_for(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < limit {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

fn failed(r: Result<impl std::fmt::Debug, VmmError>) -> String {
    match r {
        Err(VmmError::Failed(m)) => m,
        other => panic!("expected Failed, got {other:?}"),
    }
}

const LONG: Duration = Duration::from_secs(10);

#[test]
fn create_writes_spec_and_overlay() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    assert_eq!(h.id.as_str(), "b1");
    assert_eq!(h.driver, "ch-v54.0");
    let data: serde_json::Value = serde_json::from_str(&h.data).unwrap();
    assert_eq!(
        data,
        serde_json::json!({"launcher": "child", "image": format!("base-{HEX}")})
    );
    let p = w.paths("b1");
    assert_eq!(std::fs::read_to_string(p.root_disk()).unwrap(), "qcow\n");
    let qargv = std::fs::read_to_string(w.root.join("t/qemu-argv")).unwrap();
    assert!(qargv.ends_with("8G\n"), "{qargv}");
    assert!(qargv.contains(&format!("{}\n", w.image.raw.display())));
    let s = read_spec(&p).unwrap();
    assert_eq!(s.id.as_str(), "b1");
    assert_eq!((s.vcpus, s.mem_mib), (2, 4096));
    assert_eq!(s.base, w.image.raw);
    assert_eq!(s.boot, w.image.boot);
    assert!(s.landlock);
    assert!(!s.repo && !s.restore);
    // repo.img and a snapshot are picked up on the next create
    std::fs::write(p.repo_disk(), b"r").unwrap();
    std::fs::create_dir(p.snapshot_dir()).unwrap();
    std::fs::write(p.snapshot_dir().join("config.json"), b"{}").unwrap();
    v.create(&w.spec("b1")).unwrap();
    let s = read_spec(&p).unwrap();
    assert!(s.repo && s.restore);
}

#[test]
fn create_refuses_small_disk() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let mut spec = w.spec("b1");
    spec.size.disk_gib = 2;
    assert_eq!(
        failed(v.create(&spec)),
        "the box disk (2 GiB) is smaller than the base image (4 GiB)"
    );
    assert!(!w.paths("b1").root_disk().exists());
    assert!(!w.paths("b1").vm_json().exists());
}

#[test]
fn create_keeps_existing_overlay() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let spec = w.spec("b1");
    std::fs::write(w.paths("b1").root_disk(), b"keep").unwrap();
    v.create(&spec).unwrap();
    assert_eq!(
        std::fs::read_to_string(w.paths("b1").root_disk()).unwrap(),
        "keep"
    );
    assert!(!w.root.join("t/qemu-argv").exists(), "qemu-img ran");
}

#[test]
fn create_refuses_long_socket_paths() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let id = "x".repeat(40);
    let m = failed(v.create(&w.spec(&id)));
    assert!(m.contains("socket"), "{m}");
    let mut spec = w.spec("b1");
    spec.dir = w.root.join("i");
    assert!(v.create(&spec).is_err(), "a dir that is not <boxes>/<id>");
}

#[test]
fn boot_runs_hooks_then_vmm() {
    let w = World::new();
    let l = w.launcher(&[]);
    let v = w.vmm_with(l, vec![w.hook("h1", false), w.hook("h2", false)]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    assert_eq!(w.events(), ["h1.before", "h2.before"]);
    let p = w.paths("b1");
    let want: Vec<String> = argv(&read_spec(&p).unwrap(), &p)
        .into_iter()
        .map(|a| a.into_string().unwrap())
        .collect();
    let got: Vec<String> = std::fs::read_to_string(p.dir.join("fake-ch.argv"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(got, want);
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn hook_failure_fails_boot_and_unwinds() {
    let w = World::new();
    let l = w.launcher(&[]);
    let v = w.vmm_with(
        l,
        vec![w.hook("h1", false), w.hook("h2", true), w.hook("h3", false)],
    );
    let h = w.create(&v, "b1");
    let m = failed(v.boot(&h));
    assert!(m.contains("bind failed"), "{m}");
    assert_eq!(w.events(), ["h1.before", "h2.before", "h1.off"]);
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
    assert_eq!(v.status(&h), VmStatus::Off);
}

#[test]
fn early_exit_reports_ch_log() {
    let w = World::new();
    let (v, l) = w.vmm(&[("FAKE_CH_EXIT_AT_START", "1")]);
    let h = w.create(&v, "b1");
    let mut old = String::new();
    for i in 0..30 {
        old.push_str(&format!("old line {i}\n"));
    }
    old.push_str("bad \x1b[31m escape\n");
    std::fs::write(w.paths("b1").ch_log(), old).unwrap();
    let t = Instant::now();
    let m = failed(v.boot(&h));
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(m.starts_with("the VMM exited at start; see ch.log"), "{m}");
    assert!(m.contains("old line 29"), "{m}");
    assert!(!m.contains("old line 10\n"), "only the last 20 lines: {m}");
    assert!(m.contains("bad ?[31m escape"), "{m}");
    assert!(!m.contains('\x1b'));
    assert_eq!(w.events(), ["h.before", "h.off"]);
    assert_eq!(l.exit_status(&h.id).and_then(|s| s.code()), Some(1));
    assert_eq!(v.status(&h), VmStatus::Off);
}

#[test]
fn pause_resume_and_status() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    assert_eq!(v.status(&h), VmStatus::Running);
    v.pause(&h).unwrap();
    assert_eq!(v.status(&h), VmStatus::Paused);
    let m = failed(v.pause(&h));
    assert!(m.contains("500"), "{m}");
    v.resume(&h).unwrap();
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn stop_returns_within_a_second() {
    let w = World::new();
    let (v, _l) = w.vmm(&[("FAKE_CH_HANG", "1")]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let t = Instant::now();
    v.stop(&h).unwrap();
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
}

#[test]
fn stop_ladder_escalates() {
    let w = World::new();
    let (v, l) = w.vmm(&[("FAKE_CH_IGNORE_POWER", "1")]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let t = Instant::now();
    v.stop(&h).unwrap();
    assert!(wait_for(Duration::from_secs(3), || l
        .exit_status(&h.id)
        .is_some()));
    assert!(
        t.elapsed() >= Duration::from_millis(900),
        "waited for power"
    );
    // vmm.shutdown exits 0; a kill would be a signal
    assert_eq!(l.exit_status(&h.id).unwrap().code(), Some(0));
    assert!(wait_for(LONG, || v.status(&h) == VmStatus::Off));
}

#[test]
fn stop_ladder_force_stops_a_hung_vmm() {
    let w = World::new();
    let (v, l) = w.vmm(&[("FAKE_CH_HANG", "1")]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.stop(&h).unwrap();
    assert!(wait_for(Duration::from_secs(15), || l
        .exit_status(&h.id)
        .is_some()));
    assert_eq!(l.exit_status(&h.id).unwrap().signal(), Some(9));
    assert!(wait_for(LONG, || v.status(&h) == VmStatus::Off));
    assert!(wait_for(LONG, || w.events() == ["h.before", "h.off"]));
    assert!(!w.paths("b1").api_sock().exists());
}

#[test]
fn stop_twice_is_ok() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.stop(&h).unwrap();
    v.stop(&h).unwrap();
    assert!(wait_for(LONG, || v.status(&h) == VmStatus::Off));
    v.stop(&h).unwrap();
    assert!(wait_for(LONG, || !w.paths("b1").api_sock().exists()));
}

#[test]
fn snapshot_needs_pause() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let p = w.paths("b1");
    let m = failed(v.snapshot(&h, &p.snapshot_dir()));
    assert!(m.contains("pause first"), "{m}");
    std::fs::create_dir(p.snapshot_dir()).unwrap();
    std::fs::write(p.snapshot_dir().join("stale"), b"x").unwrap();
    v.pause(&h).unwrap();
    v.snapshot(&h, &p.snapshot_dir()).unwrap();
    assert!(p.snapshot_dir().join("config.json").exists());
    assert!(!p.snapshot_dir().join("stale").exists());
}

#[test]
fn snapshot_refuses_other_dest() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    let other = w.root.join("i");
    assert!(v.snapshot(&h, &other).is_err());
    assert!(w.root.join("i/base").exists(), "nothing was removed");
    assert!(v.snapshot(&h, Path::new("/")).is_err());
}

#[test]
fn restore_boots_paused_then_resumes() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let p = w.paths("b1");
    w.spec("b1");
    std::fs::create_dir(p.snapshot_dir()).unwrap();
    std::fs::write(p.snapshot_dir().join("config.json"), b"{}").unwrap();
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let argv = std::fs::read_to_string(p.dir.join("fake-ch.argv")).unwrap();
    assert!(argv.starts_with("\"--restore\"\n"), "{argv}");
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn status_after_restart_uses_the_api() {
    let w = World::new();
    let (v1, _l1) = w.vmm(&[]);
    let h = w.create(&v1, "b1");
    v1.boot(&h).unwrap();
    let (v2, _l2) = w.vmm(&[]);
    w.track(&v2, &h);
    assert_eq!(v2.status(&h), VmStatus::Running);
    v1.pause(&h).unwrap();
    assert_eq!(v2.status(&h), VmStatus::Paused);
}

#[test]
fn status_of_created_unbooted_is_off() {
    let w = World::new();
    let (v1, _l1) = w.vmm(&[]);
    let h = w.create(&v1, "b1");
    assert_eq!(v1.status(&h), VmStatus::Off);
    let (v2, _l2) = w.vmm(&[]);
    assert_eq!(v2.status(&h), VmStatus::Off);
    w.spec("b2");
    let h2 = VmHandle {
        id: BoxId::parse("b2").unwrap(),
        ..h.clone()
    };
    assert_eq!(v2.status(&h2), VmStatus::Gone);
}

#[test]
fn stop_after_restart_without_child() {
    let w = World::new();
    let (v1, l1) = w.vmm(&[]);
    let h = w.create(&v1, "b1");
    v1.boot(&h).unwrap();
    let (v2, _l2) = w.vmm(&[]);
    w.track(&v2, &h);
    let t = Instant::now();
    v2.stop(&h).unwrap();
    assert!(t.elapsed() < Duration::from_secs(1));
    assert!(wait_for(LONG, || l1.exit_status(&h.id).is_some()));
    assert_eq!(l1.exit_status(&h.id).unwrap().code(), Some(0));
    assert!(wait_for(LONG, || v2.status(&h) == VmStatus::Off));
    assert!(wait_for(LONG, || v1.status(&h) == VmStatus::Off));
    v2.stop(&h).unwrap();
}

#[test]
fn after_off_runs_once() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.stop(&h).unwrap();
    assert!(wait_for(LONG, || w.events() == ["h.before", "h.off"]));
    v.stop(&h).unwrap();
    v.destroy(&h).unwrap();
    v.destroy(&h).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(w.events(), ["h.before", "h.off"]);
    // a second run gets its own after_off
    std::fs::remove_file(w.paths("b1").dir.join("fake-ch.argv")).unwrap();
    v.boot(&h).unwrap();
    v.destroy(&h).unwrap();
    assert_eq!(w.events(), ["h.before", "h.off", "h.before", "h.off"]);
}

#[test]
fn destroy_is_idempotent() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.destroy(&h).unwrap();
    v.boot(&h).unwrap();
    v.destroy(&h).unwrap();
    assert!(
        l.exit_status(&h.id).is_some(),
        "destroy waited for the exit"
    );
    assert_eq!(v.status(&h), VmStatus::Off);
    v.destroy(&h).unwrap();
    assert!(w.paths("b1").vm_json().exists(), "destroy keeps files");
    assert!(w.paths("b1").root_disk().exists());
}
