#![cfg(all(unix, feature = "fake"))]
//! `ChVmm` against `saiife-fake-ch` (plan 35, Task 5). No real VMM runs.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use saiife_boxes::template::{AgentKind, ImageRef, Size};
use saiife_boxes::vmm::{VmHandle, VmSpec, VmStatus, Vmm, VmmError};
use saiife_boxhost::launch::{
    argv, read_spec, Boot, ChildLauncher, FakeUnitBus, Launcher, UnitLauncher,
};
use saiife_boxhost::layout::Layout;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::pins::sha256_file;
use saiife_boxhost::tools::Tools;
use saiife_boxhost::vmm::{
    missing_agent, ChVmm, ChVmmInit, ImageResolver, ResolvedImage, StopTimes, VmHooks,
};
use saiife_wire::source::BoxId;
use std::os::unix::fs::OpenOptionsExt;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixed(ResolvedImage);
impl ImageResolver for Fixed {
    fn resolve(&self, _r: &ImageRef) -> Result<ResolvedImage, String> {
        Ok(self.0.clone())
    }
}

/// Records hook calls as "<name>.before" / "<name>.off" / "<name>.refused".
struct Rec {
    name: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    fail: bool,
    delay: Duration,
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
        std::thread::sleep(self.delay);
        if self.fail {
            Err("bind failed".into())
        } else {
            Ok(())
        }
    }
    fn after_off(&self, _id: &BoxId) {
        self.log.lock().unwrap().push(format!("{}.off", self.name));
    }
    fn restore_refused(&self, _id: &BoxId, why: &str) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}.refused", self.name));
        self.log.lock().unwrap().push(format!("why: {why}"));
    }
}

struct World {
    root: PathBuf,
    /// The daemon's record dirs (R37): `VmSpec.dir` is `<records>/<id>`.
    records: PathBuf,
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
        for d in ["i", "v", "t", "r"] {
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
            vault: root.join("vault"),
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
            agents: vec!["claude-code".into()],
        };
        World {
            records: root.join("r"),
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
        let mut l = ChildLauncher::direct(
            PathBuf::from(env!("CARGO_BIN_EXE_saiife-fake-ch")),
            self.layout.vault.clone(),
        );
        for (k, v) in env {
            l = l.env(k, v);
        }
        let l = Arc::new(l);
        self.launchers.lock().unwrap().push(Arc::clone(&l));
        l
    }

    fn vmm_with<L: Launcher + 'static>(
        &self,
        launcher: Arc<L>,
        hooks: Vec<Arc<dyn VmHooks>>,
    ) -> Arc<ChVmm> {
        self.vmm_uid(launcher, hooks, rustix::process::geteuid().as_raw())
    }

    fn vmm_uid<L: Launcher + 'static>(
        &self,
        launcher: Arc<L>,
        hooks: Vec<Arc<dyn VmHooks>>,
        vmm_uid: u32,
    ) -> Arc<ChVmm> {
        let stop = StopTimes {
            power_s: 1,
            shutdown_s: 1,
            force_s: 2,
        };
        self.vmm_times(launcher, hooks, vmm_uid, stop)
    }

    fn vmm_times<L: Launcher + 'static>(
        &self,
        launcher: Arc<L>,
        hooks: Vec<Arc<dyn VmHooks>>,
        vmm_uid: u32,
        stop: StopTimes,
    ) -> Arc<ChVmm> {
        Arc::new(ChVmm::new(ChVmmInit {
            vmm_uid,
            records: self.records.clone(),
            layout: self.layout.clone(),
            tools: self.tools.clone(),
            images: Arc::new(Fixed(self.image.clone())),
            launcher,
            hooks,
            landlock: true,
            stop,
        }))
    }

    fn hook(&self, name: &'static str, fail: bool) -> Arc<dyn VmHooks> {
        self.slow_hook(name, fail, Duration::ZERO)
    }

    fn slow_hook(&self, name: &'static str, fail: bool, delay: Duration) -> Arc<dyn VmHooks> {
        Arc::new(Rec {
            name,
            log: Arc::clone(&self.log),
            fail,
            delay,
        })
    }

    fn marker(&self, id: &str) -> PathBuf {
        self.layout.vault.join(format!("{id}.marker"))
    }

    /// The verified snapshot copy in the vault.
    fn snap(&self, id: &str) -> PathBuf {
        self.layout.vault.join(format!("{id}.snap"))
    }

    fn pid_record(&self, id: &str) -> PathBuf {
        self.layout.vault.join(format!("{id}.pid"))
    }

    /// Re-sign the marker over the vault copy as it is now.
    fn resign(&self, id: &str) {
        let mut files = serde_json::Map::new();
        for e in std::fs::read_dir(self.snap(id)).unwrap() {
            let e = e.unwrap();
            files.insert(
                e.file_name().into_string().unwrap(),
                sha256_file(&e.path()).unwrap().into(),
            );
        }
        let m = serde_json::json!({"version": 2, "files": files});
        std::fs::write(self.marker(id), m.to_string()).unwrap();
    }

    /// Boot, pause, snapshot, stop: a box with a good snapshot and marker.
    fn snapshotted(&self, v: &Arc<ChVmm>, id: &str) -> VmHandle {
        let h = self.create(v, id);
        v.boot(&h).unwrap();
        v.pause(&h).unwrap();
        v.snapshot(&h, &self.dest(id)).unwrap();
        assert!(self.marker(id).exists(), "snapshot writes the marker");
        assert!(
            self.snap(id).join("config.json").exists(),
            "and the vault copy"
        );
        assert!(
            is_empty_dir(&self.paths(id).snapshot_dir()),
            "copied out of the box dir, which is kept empty"
        );
        self.halt(v, &h);
        std::fs::remove_file(self.paths(id).dir.join("fake-ch.argv")).unwrap();
        self.log.lock().unwrap().clear();
        h
    }

    /// Stop the VM and wait for its exit and its `after_off` (hook "h"):
    /// what `destroy` used to be before it removed the runtime dir (R37).
    fn halt(&self, v: &Arc<ChVmm>, h: &VmHandle) {
        let offs = || self.events().iter().filter(|e| *e == "h.off").count();
        let before = offs();
        v.stop(h).unwrap();
        assert!(wait_for(LONG, || v.status(h) == VmStatus::Off));
        assert!(wait_for(LONG, || offs() > before), "{:?}", self.events());
    }

    /// Edit the snapshot's config.json and re-sign the marker to match, as a
    /// VMM that could forge the marker would (it cannot; this isolates the
    /// config checks from the digest check).
    fn forge(&self, id: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let cfg = self.snap(id).join("config.json");
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
        edit(&mut v);
        std::fs::write(&cfg, serde_json::to_vec(&v).unwrap()).unwrap();
        self.resign(id);
    }

    /// Rewrites the vault copy's state.json (raw bytes) and re-signs it.
    fn forge_state(&self, id: &str, edit: impl FnOnce(&mut serde_json::Value) -> Vec<u8>) {
        let p = self.snap(id).join("state.json");
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let body = edit(&mut v);
        std::fs::write(&p, body).unwrap();
        self.resign(id);
    }

    fn booted_cold(&self, id: &str) -> bool {
        let argv = std::fs::read_to_string(self.paths(id).dir.join("fake-ch.argv")).unwrap();
        !argv.contains("\"--restore\"")
    }

    fn vmm(&self, env: &[(&str, &str)]) -> (Arc<ChVmm>, Arc<ChildLauncher>) {
        let l = self.launcher(env);
        let h = self.hook("h", false);
        (self.vmm_with(Arc::clone(&l), vec![h]), l)
    }

    /// The record dir's `snapshot`: what the manager passes to `snapshot`.
    fn dest(&self, id: &str) -> PathBuf {
        self.records.join(id).join("snapshot")
    }

    /// The spec of a box: `dir` is its record dir (made here, as the store
    /// does). Its runtime dir is made too, so tests can plant files in it
    /// before `create`; `create` accepts a runtime dir of this uid.
    fn spec(&self, id: &str) -> VmSpec {
        let rt = self.root.join(id);
        if !rt.exists() {
            std::fs::create_dir(&rt).unwrap();
        }
        let dir = self.records.join(id);
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
            agent: AgentKind::ClaudeCode,
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
        // destroy is bounded (R41): retry it while a stop ladder runs
        for (v, h) in &all {
            let _ = destroy_eventually(v, h);
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

/// `destroy` until it succeeds, as the manager's tick retries it (R41);
/// the last error after `LONG`.
fn destroy_eventually(v: &ChVmm, h: &VmHandle) -> Result<(), VmmError> {
    let t = Instant::now();
    loop {
        match v.destroy(h) {
            Ok(()) => return Ok(()),
            Err(e) if t.elapsed() >= LONG => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
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
        serde_json::json!({"launcher": "child", "image": format!("base-{HEX}"), "mem_mib": 4096, "vcpus": 2, "repo": false, "tier": "m"})
    );
    // The manager learns the image through the driver (plan 36).
    assert_eq!(v.image_id(&h), Some(format!("base-{HEX}")));
    for data in [
        String::new(),
        "not json".to_string(),
        r#"{"image": "../etc"}"#.to_string(),
        r#"{"image": 7}"#.to_string(),
        format!(
            r#"{{"image": "base-{HEX}", "pad": "{}"}}"#,
            "x".repeat(5000)
        ),
    ] {
        let other = VmHandle { data, ..h.clone() };
        assert_eq!(
            v.image_id(&other),
            None,
            "{}",
            &other.data[..other.data.len().min(40)]
        );
    }
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
    assert!(!s.repo && s.restore.is_none());
    // a repo.img in the (VMM-writable) runtime dir is not the box's: only
    // one create hands over from the record dir counts; a snapshot is not
    // trusted by create (boot decides, from the marker)
    std::fs::write(p.repo_disk(), b"r").unwrap();
    std::fs::create_dir(p.snapshot_dir()).unwrap();
    std::fs::write(p.snapshot_dir().join("config.json"), b"{}").unwrap();
    let h2 = v.create(&w.spec("b1")).unwrap();
    let s = read_spec(&p).unwrap();
    assert!(!s.repo && s.restore.is_none());
    assert!(h2.data.contains("\"repo\":false"), "{}", h2.data);
    std::fs::remove_file(p.repo_disk()).unwrap();
    let spec = w.spec("b1");
    std::fs::write(spec.dir.join("repo.img"), b"r").unwrap();
    let h3 = v.create(&spec).unwrap();
    assert!(read_spec(&p).unwrap().repo);
    assert!(h3.data.contains("\"repo\":true"), "{}", h3.data);
}

#[test]
fn create_refuses_small_disk() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let mut spec = w.spec("b1");
    spec.size.disk_gib = 2;
    // a repo disk spawn placed in the record stays there (R40): a failed
    // create never leaves it in the VMM-readable runtime dir
    std::fs::write(spec.dir.join("repo.img"), b"repo").unwrap();
    assert_eq!(
        failed(v.create(&spec)),
        "the box disk (2 GiB) is smaller than the base image (4 GiB)"
    );
    assert!(!w.paths("b1").root_disk().exists());
    assert!(!w.paths("b1").vm_json().exists());
    assert!(!w.paths("b1").repo_disk().exists());
    assert_eq!(std::fs::read(spec.dir.join("repo.img")).unwrap(), b"repo");
}

#[test]
fn boot_refuses_missing_agent() {
    let w = World::new();
    assert_eq!(w.image.agents, vec!["claude-code".to_string()]);
    let (v, _l) = w.vmm(&[]);
    // the record dir only, as the store makes it: create makes the runtime
    // dir, and must not get that far
    let dir = w.records.join("b1");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("repo.img"), b"repo").unwrap();
    for agent in [AgentKind::Codex, AgentKind::Gemini] {
        let spec = VmSpec {
            id: BoxId::parse("b1").unwrap(),
            size: Size {
                disk_gib: 8,
                ..Size::default()
            },
            image: ImageRef::Default,
            agent,
            dir: dir.clone(),
        };
        let e = failed(v.create(&spec));
        assert_eq!(e, missing_agent(&format!("base-{HEX}"), agent));
        assert_eq!(
            e,
            format!(
                "the image base-{HEX} has no {}: build one with \"saiife box image build --with {}\"",
                agent.name(),
                agent.name()
            )
        );
        assert!(!w.root.join("b1").exists(), "no runtime dir");
        assert!(!w.paths("b1").root_disk().exists(), "no overlay");
        assert!(!w.root.join("t/qemu-argv").exists(), "qemu-img never ran");
        assert_eq!(std::fs::read(dir.join("repo.img")).unwrap(), b"repo");
    }
    // the same image with the agent baked in boots it
    let mut w2 = World::new();
    w2.image.agents.push("codex".into());
    let (v2, _l2) = w2.vmm(&[]);
    let mut spec = w2.spec("b1");
    spec.agent = AgentKind::Codex;
    v2.create(&spec).unwrap();
    // Claude Code is in every image
    assert!(w.create(&v, "b2").id.as_str() == "b2");
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

/// F1: a bus that cannot say whether the unit runs is "still running": the
/// boot is refused, no second VMM on the same disks.
#[test]
fn unit_bus_error_refuses_boot() {
    let w = World::new();
    let (v0, _l) = w.vmm(&[]);
    let h = w.create(&v0, "b1");
    let bus = Arc::new(FakeUnitBus::new());
    *bus.active.lock().unwrap() = Err("bus unreachable".into());
    let v = w.vmm_with(Arc::new(UnitLauncher::new(bus.clone())), vec![]);
    let m = failed(v.boot(&h));
    assert!(m.contains("still running"), "{m}");
    assert!(!bus
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("start")));
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
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
    let m = failed(v.snapshot(&h, &w.dest("b1")));
    assert!(m.contains("pause first"), "{m}");
    // the launcher made the dir; a stale file in it is cleared first
    std::fs::write(p.snapshot_dir().join("stale"), b"x").unwrap();
    v.pause(&h).unwrap();
    v.snapshot(&h, &w.dest("b1")).unwrap();
    // sealed into the vault, read-only, the stale file gone
    let snap = w.snap("b1");
    assert!(snap.join("config.json").exists());
    assert!(!snap.join("stale").exists() && is_empty_dir(&p.snapshot_dir()));
    let mode = |q: &Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&snap), 0o750);
    assert_eq!(mode(&snap.join("memory-ranges")), 0o640);
    let m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(w.marker("b1")).unwrap()).unwrap();
    let names: Vec<&String> = m["files"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["config.json", "memory-ranges", "state.json"]);
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
    let h = w.snapshotted(&v, "b1");
    let p = w.paths("b1");
    v.boot(&h).unwrap();
    let argv = std::fs::read_to_string(p.dir.join("fake-ch.argv")).unwrap();
    assert!(argv.starts_with("\"--restore\"\n"), "{argv}");
    let src = format!("source_url=file://{}", w.snap("b1").display());
    assert!(argv.contains(&format!("\"{src}\"")), "{argv}");
    assert_eq!(read_spec(&p).unwrap().restore, Some(w.snap("b1")));
    assert_eq!(v.status(&h), VmStatus::Running);
    assert!(!w.events().iter().any(|e| e.ends_with(".refused")));
    // one-shot: the marker is gone, the next boot is cold
    assert!(!w.marker("b1").exists());
    assert!(!w.snap("b1").exists(), "a spent snapshot is discarded");
    w.halt(&v, &h);
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
    assert!(read_spec(&p).unwrap().restore.is_none());
}

#[test]
fn restore_refuses_a_planted_snapshot() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    std::fs::remove_file(w.marker("b1")).unwrap();
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
    assert!(read_spec(&w.paths("b1")).unwrap().restore.is_none());
    assert!(
        w.events().contains(&"h.refused".to_string()),
        "{:?}",
        w.events()
    );
}

#[test]
fn restore_refuses_a_tampered_config() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    let cfg = w.snap("b1").join("config.json");
    let mut c = std::fs::read(&cfg).unwrap();
    c.push(b' ');
    std::fs::write(&cfg, c).unwrap();
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
    assert!(
        w.events().contains(&"h.refused".to_string()),
        "{:?}",
        w.events()
    );
    assert!(!w.marker("b1").exists(), "a refused marker is dropped");
}

#[test]
fn restore_refuses_a_foreign_disk() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    w.forge("b1", |c| {
        c["disks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"path": "/etc/shadow"}));
    });
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
    let ev = w.events();
    assert!(ev.contains(&"h.refused".to_string()), "{ev:?}");
    assert!(
        ev.iter()
            .any(|e| e.starts_with("why:") && e.contains("disk")),
        "{ev:?}"
    );
}

#[test]
fn restore_refuses_landlock_off_and_extra_devices() {
    type Edit = fn(&mut serde_json::Value);
    let edits: [(&str, Edit); 5] = [
        ("landlock", |c| c["landlock_enable"] = false.into()),
        ("landlock", |c| {
            c["landlock_rules"] = serde_json::json!([{"path": "/", "access": "rw"}])
        }),
        ("net", |c| c["net"] = serde_json::json!([{"tap": "tap0"}])),
        ("payload", |c| {
            c["payload"]["firmware"] = "/etc/passwd".into()
        }),
        ("vsock", |c| c["vsock"]["socket"] = "/elsewhere.sock".into()),
    ];
    for (what, edit) in edits {
        let w = World::new();
        let (v, _l) = w.vmm(&[]);
        let h = w.snapshotted(&v, "b1");
        w.forge("b1", edit);
        v.boot(&h).unwrap();
        assert!(w.booted_cold("b1"), "{what}");
        let ev = w.events();
        assert!(
            ev.iter().any(|e| e.starts_with("why:") && e.contains(what)),
            "{what}: {ev:?}"
        );
    }
}

#[test]
fn ch_log_fifo_does_not_block_start() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let p = w.paths("b1");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        p.ch_log(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (l2, id, p2) = (Arc::clone(&l), h.id.clone(), p.clone());
    std::thread::spawn(move || {
        let _ = tx.send(l2.start(&id, &p2));
    });
    let got = rx.recv_timeout(Duration::from_secs(5));
    if got.is_err() {
        // unblock the stuck open before failing
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(p.ch_log());
        let _ = rx.recv_timeout(Duration::from_secs(5));
        let _ = l.force_stop(&h.id);
        panic!("start blocked on a FIFO ch.log");
    }
    match got.unwrap() {
        Ok(()) => {
            let m = std::fs::symlink_metadata(p.ch_log()).unwrap();
            assert!(m.file_type().is_file(), "the FIFO was replaced");
            l.force_stop(&h.id).unwrap();
        }
        Err(e) => assert!(e.contains("ch.log"), "{e}"),
    }
}

#[test]
fn ch_log_symlink_is_refused() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let p = w.paths("b1");
    let target = w.root.join("t/target");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, p.ch_log()).unwrap();
    let e = l.start(&h.id, &p).unwrap_err();
    assert!(e.contains("ch.log"), "{e}");
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!p.dir.join("fake-ch.argv").exists(), "nothing started");
    let m = failed(v.boot(&h));
    assert!(m.contains("ch.log"), "{m}");
}

#[test]
fn api_sock_symlink_is_not_followed() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h1 = w.create(&v, "b1");
    let h2 = w.create(&v, "b2");
    v.boot(&h2).unwrap();
    std::os::unix::fs::symlink(w.paths("b2").api_sock(), w.paths("b1").api_sock()).unwrap();
    assert_eq!(v.status(&h1), VmStatus::Off);
    assert!(v.pause(&h1).is_err());
    v.stop(&h1).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        v.status(&h2),
        VmStatus::Running,
        "the other box was untouched"
    );
}

#[test]
fn unconfirmed_stop_is_not_off() {
    let w = World::new();
    let (v1, _l1) = w.vmm(&[("FAKE_CH_HANG", "1")]);
    let h = w.create(&v1, "b1");
    v1.boot(&h).unwrap();
    let (v2, _l2) = w.vmm(&[]);
    w.track(&v2, &h);
    v2.stop(&h).unwrap();
    // v2 has no child to force-stop: the ladder cannot confirm the exit
    assert!(v2.destroy(&h).is_err());
    assert_ne!(v2.status(&h), VmStatus::Off);
    // v1 owns the child; the World guard stops it
}

#[test]
fn concurrent_boots_have_one_winner() {
    let w = World::new();
    let l = w.launcher(&[]);
    let v = w.vmm_with(l, vec![w.slow_hook("h", false, Duration::from_millis(300))]);
    let h = w.create(&v, "b1");
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| v.boot(&h));
        std::thread::sleep(Duration::from_millis(50));
        let b = s.spawn(|| v.boot(&h));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!(a.is_ok(), "{a:?}");
    let m = failed(b);
    assert!(m.contains("already"), "{m}");
    assert_eq!(w.events(), ["h.before"]);
    assert!(w.paths("b1").api_sock().exists());
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn stop_during_boot_is_applied() {
    let w = World::new();
    let l = w.launcher(&[]);
    let v = w.vmm_with(l, vec![w.slow_hook("h", false, Duration::from_millis(300))]);
    let h = w.create(&v, "b1");
    std::thread::scope(|s| {
        let a = s.spawn(|| v.boot(&h));
        std::thread::sleep(Duration::from_millis(100));
        v.stop(&h).unwrap();
        a.join().unwrap().unwrap();
    });
    assert!(wait_for(LONG, || v.status(&h) == VmStatus::Off));
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
    // a second run gets its own after_off (destroy removed the runtime dir:
    // the box is created again)
    let h = w.create(&v, "b1");
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
    v.destroy(&h).unwrap();
    assert_eq!(v.status(&h), VmStatus::Gone);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.destroy(&h).unwrap();
    assert!(
        l.exit_status(&h.id).is_some(),
        "destroy waited for the exit"
    );
    assert_eq!(v.status(&h), VmStatus::Gone);
    v.destroy(&h).unwrap();
}

/// R37: after a confirmed exit, destroy removes the box's runtime dir (by
/// fd, `snapshot/` emptied first) and its vault entries; the record dir is
/// the store's and is left alone.
#[test]
fn destroy_removes_the_runtime_dir_after_a_confirmed_exit() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    assert!(w.marker("b1").exists());
    std::fs::write(w.paths("b1").snapshot_dir().join("left"), b"x").unwrap();
    std::fs::write(w.records.join("b1").join("box.json"), b"{}").unwrap();
    let outside = w.root.join("outside");
    std::fs::write(&outside, b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, w.paths("b1").dir.join("link")).unwrap();
    v.destroy(&h).unwrap();
    assert!(!w.paths("b1").dir.exists(), "the runtime dir is gone");
    assert!(!w.marker("b1").exists() && !w.snap("b1").exists());
    assert!(!w.pid_record("b1").exists());
    assert!(
        w.records.join("b1").join("box.json").exists(),
        "records stay"
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"keep",
        "a link is unlinked, not followed"
    );
    // an unexpected subdirectory keeps the runtime dir (and destroy fails)
    let h = w.create(&v, "b2");
    std::fs::create_dir(w.paths("b2").dir.join("planted")).unwrap();
    assert!(v.destroy(&h).is_err());
    assert!(w.paths("b2").vm_json().exists());
    std::fs::remove_dir(w.paths("b2").dir.join("planted")).unwrap();
}

/// I1 (R19): after a daemon restart (a new ChVmm and launcher, no run), a
/// live VMM whose API says Shutdown is not Off, and destroy neither skips
/// the stop nor removes its runtime dir or pid record while the launcher
/// says it is alive.
#[test]
fn a_live_vmm_saying_shutdown_is_not_off_and_not_destroyed() {
    let w = World::new();
    let (v1, _l1) = w.vmm(&[("FAKE_CH_SAYS_SHUTDOWN", "1")]);
    let h = w.create(&v1, "b1");
    v1.boot(&h).unwrap();
    let l2 = w.launcher(&[]);
    let v2 = w.vmm_with(Arc::clone(&l2), vec![]);
    assert_eq!(l2.exited(&h.id), Some(false), "alive by the pid record");
    assert_ne!(v2.status(&h), VmStatus::Off);
    assert!(v2.destroy(&h).is_err());
    assert!(w.paths("b1").vm_json().exists(), "the runtime dir is kept");
    assert!(w.pid_record("b1").exists(), "the pid record is kept");
    assert_eq!(l2.exited(&h.id), Some(false));
    // v1 owns the child; the World guard stops it
}

/// M2: the personal runtime root is the user's alone: a looser one of ours
/// is made 0700, a symlinked one refused.
#[test]
fn personal_runtime_root_is_made_private() {
    let mut w = World::new();
    let rt = w.root.join("rt");
    std::fs::create_dir(&rt).unwrap();
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o755)).unwrap();
    w.layout.boxes = rt.clone();
    let (v, _l) = w.vmm(&[]);
    let spec = w.spec("b1");
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    assert_eq!(mode_of(&rt), 0o700);
    let link = w.root.join("rtlink");
    std::os::unix::fs::symlink(&rt, &link).unwrap();
    w.layout.boxes = link;
    let (v, _l) = w.vmm(&[]);
    let m = failed(v.create(&w.spec("b2")));
    assert!(m.contains("runtime root"), "{m}");
}

/// R37: `VmSpec.dir` must be the record dir `<records>/<id>`; the runtime
/// dir is the driver's own (`<layout.boxes>/<id>`), made 0700 personal,
/// 2770 locked, and refused when it is a link or not this uid's.
#[test]
fn create_takes_the_record_dir_and_makes_the_runtime_dir() {
    let mut w = World::new();
    let (v, _l) = w.vmm(&[]);
    let mut spec = w.spec("b1");
    spec.dir = w.paths("b1").dir;
    let m = failed(v.create(&spec));
    assert!(m.contains("record dir"), "{m}");
    let spec = w.spec("b2");
    std::fs::remove_dir(w.paths("b2").dir).unwrap();
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    assert_eq!(mode_of(&w.paths("b2").dir), 0o700);
    assert!(w.paths("b2").vm_json().exists());
    assert!(
        !w.records.join("b2").join("vm.json").exists(),
        "nothing VMM-side in records"
    );
    // a symlinked runtime dir is refused, its target untouched
    let spec = w.spec("b3");
    std::fs::remove_dir(w.paths("b3").dir).unwrap();
    let elsewhere = w.root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, w.paths("b3").dir).unwrap();
    let m = failed(v.create(&spec));
    assert!(m.contains("runtime dir"), "{m}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    // locked: 2770 (setgid: the VMM user's group is kept)
    w.layout.locked = true;
    let (v, _l) = w.vmm(&[]);
    let spec = w.spec("b4");
    std::fs::remove_dir(w.paths("b4").dir).unwrap();
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    assert_eq!(mode_of(&w.paths("b4").dir), 0o2770);
}

/// R37: the manager's dest is the record dir's `snapshot`; the VMM writes
/// into the runtime `snapshot/` and the copy is sealed into the vault. The
/// record dir gets nothing.
#[test]
fn snapshot_dest_is_checked_never_written() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    assert!(v.snapshot(&h, &w.paths("b1").snapshot_dir()).is_err());
    v.snapshot(&h, &w.dest("b1")).unwrap();
    assert!(!w.dest("b1").exists(), "the record dir gets no snapshot");
    assert!(w.snap("b1").join("config.json").exists());
}

#[test]
fn api_gone_but_child_alive_refuses_start() {
    let w = World::new();
    let (v1, _l1) = w.vmm(&[]);
    let h = w.create(&v1, "b1");
    v1.boot(&h).unwrap();
    assert!(w.pid_record("b1").exists(), "the launcher records the pid");
    // a VMM that unlinks its API socket is still alive
    std::fs::remove_file(w.paths("b1").api_sock()).unwrap();
    let (v2, _l2) = w.vmm(&[]);
    w.track(&v2, &h);
    assert_ne!(v2.status(&h), VmStatus::Off);
    let m = failed(v2.boot(&h));
    assert!(m.contains("running"), "{m}");
    assert_ne!(v1.status(&h), VmStatus::Off);
}

#[test]
fn pid_record_with_other_starttime_is_gone() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    std::fs::create_dir_all(&w.layout.vault).unwrap();
    // a live pid (this test) with another start time: a reused pid
    let rec = serde_json::json!({"pid": std::process::id(), "starttime": 1});
    std::fs::write(w.pid_record("b1"), rec.to_string()).unwrap();
    assert_eq!(l.exited(&h.id), Some(true));
    assert_eq!(v.status(&h), VmStatus::Off);
    v.boot(&h).unwrap();
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn unreadable_pid_record_fails_closed() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    std::fs::create_dir_all(&w.layout.vault).unwrap();
    std::fs::write(w.pid_record("b1"), b"not json").unwrap();
    assert_eq!(l.exited(&h.id), Some(false));
    assert_ne!(v.status(&h), VmStatus::Off);
    assert!(v.boot(&h).is_err());
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
    std::fs::remove_file(w.pid_record("b1")).unwrap();
}

#[test]
fn swapped_config_after_snapshot_is_not_used() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    let p = w.paths("b1");
    std::fs::create_dir_all(p.snapshot_dir()).unwrap();
    std::fs::write(
        p.snapshot_dir().join("config.json"),
        br#"{"disks":[{"path":"/etc/shadow"}]}"#,
    )
    .unwrap();
    v.boot(&h).unwrap();
    let argv = std::fs::read_to_string(p.dir.join("fake-ch.argv")).unwrap();
    let src = format!("source_url=file://{}", w.snap("b1").display());
    assert!(argv.contains(&format!("\"{src}\"")), "{argv}");
    assert!(
        !argv.contains(&p.snapshot_dir().display().to_string()),
        "{argv}"
    );
    assert_eq!(v.status(&h), VmStatus::Running);
}

#[test]
fn tampered_vault_copy_cold_boots() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.snapshotted(&v, "b1");
    std::fs::write(w.snap("b1").join("state.json"), b"{}").unwrap();
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
    assert!(
        w.events().contains(&"h.refused".to_string()),
        "{:?}",
        w.events()
    );
    assert!(!w.marker("b1").exists() && !w.snap("b1").exists());
    // an extra file in the copy is refused too
    v.destroy(&h).unwrap();
    let h = w.snapshotted(&v, "b1");
    std::fs::write(w.snap("b1").join("extra"), b"x").unwrap();
    v.boot(&h).unwrap();
    assert!(w.booted_cold("b1"));
}

#[test]
fn pid_record_tracks_the_child_across_launchers() {
    let w = World::new();
    let (v, l1) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let p = w.paths("b1");
    l1.start(&h.id, &p).unwrap();
    let rec = w.pid_record("b1");
    assert!(rec.exists());
    let mode = std::fs::metadata(&rec).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let vmode = std::fs::metadata(&w.layout.vault)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(vmode & 0o777, 0o700);
    // a fresh launcher (a daemon restart) sees it alive from the record
    let l2 = w.launcher(&[]);
    assert_eq!(l2.exited(&h.id), Some(false));
    assert!(l2.force_stop(&h.id).is_err(), "never signals a non-child");
    assert_eq!(l2.exited(&h.id), Some(false));
    // the owner reaps it and drops the record
    l1.force_stop(&h.id).unwrap();
    assert!(!rec.exists());
    assert_eq!(l2.exited(&h.id), None);
    // a pid that no longer exists is gone
    std::fs::write(&rec, r#"{"pid":4194303,"starttime":5}"#).unwrap();
    assert_eq!(l2.exited(&h.id), Some(true));
    // a child that exits on its own loses its record when reaped
    let l3 = w.launcher(&[("FAKE_CH_EXIT_AT_START", "0")]);
    l3.start(&h.id, &p).unwrap();
    assert!(wait_for(LONG, || l3.exited(&h.id) == Some(true)));
    assert!(!rec.exists());
}

/// An outside file the daemon owns (a stand-in for /etc/passwd), mode 0600.
fn outside(w: &World, name: &str) -> PathBuf {
    let p = w.root.join("t").join(name);
    std::fs::write(&p, b"keep").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

/// Boot, pause and snapshot with a hostile fake; the snapshot must fail and
/// leave no marker or vault copy.
fn hostile_snapshot(w: &World, evil: &str) -> String {
    let (v, _l) = w.vmm(&[("FAKE_CH_SNAP_EVIL", evil)]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (v2, h2, dest) = (Arc::clone(&v), h.clone(), w.dest("b1"));
    std::thread::spawn(move || {
        let _ = tx.send(v2.snapshot(&h2, &dest));
    });
    let r = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the snapshot blocked");
    let m = failed(r);
    assert!(!w.marker("b1").exists(), "{evil}: no marker");
    assert!(!w.snap("b1").exists(), "{evil}: no vault copy");
    m
}

#[test]
fn seal_refuses_a_symlinked_snapshot_dir() {
    let w = World::new();
    let target = w.root.join("t/owned");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let f = outside(&w, "owned/secret");
    let m = hostile_snapshot(&w, &format!("dirlink:{}", target.display()));
    assert!(m.contains("snapshot"), "{m}");
    assert_eq!(mode_of(&target), 0o700);
    assert_eq!(mode_of(&f), 0o600);
    // the target was neither moved nor emptied
    assert!(target.join("config.json").exists());
}

#[test]
fn seal_refuses_a_symlinked_entry() {
    let w = World::new();
    let f = outside(&w, "passwd");
    let passwd = mode_of(Path::new("/etc/passwd"));
    let m = hostile_snapshot(&w, &format!("link:{}", f.display()));
    assert!(m.contains("memory-ranges"), "{m}");
    assert_eq!(mode_of(&f), 0o600);
    assert_eq!(std::fs::read(&f).unwrap(), b"keep");
    assert_eq!(mode_of(Path::new("/etc/passwd")), passwd);
}

#[test]
fn seal_refuses_a_fifo_without_blocking() {
    let w = World::new();
    let m = hostile_snapshot(&w, "fifo");
    assert!(m.contains("memory-ranges"), "{m}");
}

#[test]
fn seal_refuses_a_hardlinked_entry() {
    let w = World::new();
    let f = outside(&w, "linked");
    let m = hostile_snapshot(&w, &format!("hardlink:{}", f.display()));
    assert!(m.contains("memory-ranges"), "{m}");
    assert_eq!(mode_of(&f), 0o600);
}

#[test]
fn seal_refuses_an_unexpected_file() {
    let w = World::new();
    let m = hostile_snapshot(&w, "extra");
    assert!(m.contains("extra"), "{m}");
}

#[test]
fn seal_checks_the_vmm_uid_and_copies() {
    // a VMM user other than the daemon (locked mode): files it did not
    // write are refused; the copy path never renames its dir
    let w = World::new();
    let me = rustix::process::geteuid().as_raw();
    let l = w.launcher(&[]);
    let v = w.vmm_uid(l, vec![w.hook("h", false)], me + 1);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    let m = failed(v.snapshot(&h, &w.dest("b1")));
    assert!(m.contains("owner"), "{m}");
    assert!(!w.marker("b1").exists());
    // with the right uid: a daemon-owned copy, the source dir emptied
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b2");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    v.snapshot(&h, &w.dest("b2")).unwrap();
    let meta = std::fs::metadata(w.snap("b2").join("state.json")).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), me);
    assert!(is_empty_dir(&w.paths("b2").snapshot_dir()));
}

#[test]
fn boot_refuses_a_symlinked_root_disk() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let f = outside(&w, "disk");
    let root = w.paths("b1").root_disk();
    std::fs::remove_file(&root).unwrap();
    std::os::unix::fs::symlink(&f, &root).unwrap();
    let m = failed(v.boot(&h));
    assert!(m.contains("root.qcow2"), "{m}");
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
    // a hard link is refused too
    std::fs::remove_file(&root).unwrap();
    std::fs::hard_link(&f, &root).unwrap();
    let m = failed(v.boot(&h));
    assert!(m.contains("root.qcow2"), "{m}");
}

#[test]
fn serial_log_symlink_is_not_followed() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let f = outside(&w, "bashrc");
    let serial = w.paths("b1").serial();
    std::os::unix::fs::symlink(&f, &serial).unwrap();
    v.boot(&h).unwrap();
    assert!(!std::fs::symlink_metadata(&serial).is_ok_and(|m| m.file_type().is_symlink()));
    assert_eq!(std::fs::read(&f).unwrap(), b"keep");
}

#[test]
fn starting_record_fails_closed() {
    let w = World::new();
    let (v, l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    std::fs::create_dir_all(&w.layout.vault).unwrap();
    // the daemon died between spawn and the pid record
    std::fs::write(w.pid_record("b1"), br#"{"starting":true}"#).unwrap();
    assert_eq!(l.exited(&h.id), Some(false));
    assert_ne!(v.status(&h), VmStatus::Off);
    let m = failed(v.boot(&h));
    assert!(m.contains("b1.pid"), "{m}");
    std::fs::remove_file(w.pid_record("b1")).unwrap();
}

fn ino(p: &Path) -> u64 {
    std::os::unix::fs::MetadataExt::ino(&std::fs::symlink_metadata(p).unwrap())
}

fn is_empty_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
        && std::fs::read_dir(p).unwrap().next().is_none()
}

/// Landlock binds its rule to the snapshot dir's inode when the VM is made:
/// the launcher makes the dir, and snapshot and seal only empty it.
#[test]
fn snapshot_dir_survives_seal_and_a_second_snapshot() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let dir = w.paths("b1").snapshot_dir();
    assert!(is_empty_dir(&dir), "the launcher made the snapshot dir");
    let before = ino(&dir);
    v.pause(&h).unwrap();
    v.snapshot(&h, &w.dest("b1")).unwrap();
    assert!(is_empty_dir(&dir), "seal empties, never removes");
    assert_eq!(ino(&dir), before);
    std::fs::write(dir.join("stale"), b"x").unwrap();
    v.snapshot(&h, &w.dest("b1")).unwrap();
    assert!(is_empty_dir(&dir));
    assert_eq!(ino(&dir), before);
    assert!(w.snap("b1").join("config.json").exists());
    assert!(!w.snap("b1").join("stale").exists());
}

#[test]
fn snapshot_dir_symlink_is_refused() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    let target = w.root.join("t/elsewhere");
    std::fs::create_dir(&target).unwrap();
    let keep = outside(&w, "elsewhere/keep");
    let dir = w.paths("b1").snapshot_dir();
    std::fs::remove_dir(&dir).unwrap();
    std::os::unix::fs::symlink(&target, &dir).unwrap();
    let m = failed(v.snapshot(&h, &w.dest("b1")));
    assert!(m.contains("snapshot"), "{m}");
    assert_eq!(std::fs::read(&keep).unwrap(), b"keep");
    assert!(!w.marker("b1").exists());
}

/// Locked mode: the VMM user is in the group, the overlay must be
/// group-writable (0660), set through an fd.
#[test]
fn locked_overlay_is_group_read_writable() {
    let mut w = World::new();
    w.layout.locked = true;
    let (v, _l) = w.vmm(&[]);
    let _h = w.create(&v, "b1");
    assert_eq!(mode_of(&w.paths("b1").root_disk()), 0o660);
    // personal mode leaves the tool's mode alone
    w.layout.locked = false;
    let (v, _l) = w.vmm(&[]);
    let _h = w.create(&v, "b2");
    assert_ne!(mode_of(&w.paths("b2").root_disk()) & 0o060, 0o060);
}

/// R35: a kept overlay (a restart, or an earlier create whose fchmod
/// failed) gets its locked mode again, through an fd; a link is refused.
#[test]
fn locked_overlay_mode_is_set_on_a_kept_overlay() {
    let mut w = World::new();
    w.layout.locked = true;
    let (v, _l) = w.vmm(&[]);
    let spec = w.spec("b1");
    let root = w.paths("b1").root_disk();
    std::fs::write(&root, b"qcow").unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600)).unwrap();
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    assert_eq!(mode_of(&root), 0o660);
    assert_eq!(
        std::fs::read(&root).unwrap(),
        b"qcow",
        "the overlay is kept"
    );
    // a symlink in its place is not followed
    let spec = w.spec("b2");
    let target = w.root.join("elsewhere");
    std::fs::write(&target, b"x").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, w.paths("b2").root_disk()).unwrap();
    let m = failed(v.create(&spec));
    assert!(m.contains("root disk"), "{m}");
    assert_eq!(mode_of(&target), 0o600);
}

/// A memory-ranges larger than the box's memory plus slack is refused
/// before it is copied (a host disk-fill), and nothing lands in the vault.
#[test]
fn seal_refuses_an_oversized_memory_file() {
    let w = World::new();
    let (v, _l) = w.vmm(&[("FAKE_CH_SNAP_EVIL", "huge:577")]);
    let mut spec = w.spec("b1");
    spec.size.mem_mib = 512;
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    v.boot(&h).unwrap();
    v.pause(&h).unwrap();
    let t = Instant::now();
    let m = failed(v.snapshot(&h, &w.dest("b1")));
    assert!(m.contains("memory-ranges") && m.contains("larger"), "{m}");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(!w.marker("b1").exists());
    assert!(!w.snap("b1").exists());
}

/// A unit bus whose `stop` only queues the job, as StopUnit "replace"
/// does: the unit stays active for `delay` after the call. `start` runs
/// the fake CH as a child so the API socket appears.
struct QueuedStopBus {
    fake: FakeUnitBus,
    child: Arc<ChildLauncher>,
    paths: BoxPaths,
    id: BoxId,
    delay: Duration,
    active: Arc<Mutex<bool>>,
}

impl saiife_boxhost::launch::UnitBus for QueuedStopBus {
    fn start(&self, unit: &str) -> Result<(), String> {
        self.fake.start(unit)?;
        self.child.start(&self.id, &self.paths)?;
        *self.active.lock().unwrap() = true;
        Ok(())
    }
    fn stop(&self, unit: &str) -> Result<(), String> {
        self.fake.stop(unit)?;
        let (active, child, id, delay) = (
            Arc::clone(&self.active),
            Arc::clone(&self.child),
            self.id.clone(),
            self.delay,
        );
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let _ = child.force_stop(&id);
            *active.lock().unwrap() = false;
        });
        Ok(())
    }
    fn active(&self, unit: &str) -> Result<bool, String> {
        self.fake.active(unit)?;
        Ok(*self.active.lock().unwrap())
    }
}

fn queued_vmm(w: &World, delay: Duration) -> (Arc<ChVmm>, VmHandle) {
    // the fake ignores the power button and vmm.shutdown alike
    let child = w.launcher(&[("FAKE_CH_HANG", "1")]);
    let id = BoxId::parse("b1").unwrap();
    let bus = Arc::new(QueuedStopBus {
        fake: FakeUnitBus::new(),
        child,
        paths: w.paths("b1"),
        id,
        delay,
        active: Arc::new(Mutex::new(false)),
    });
    let v = w.vmm_with(Arc::new(UnitLauncher::new(bus)), vec![w.hook("h", false)]);
    let h = w.create(&v, "b1");
    (v, h)
}

fn offs(w: &World) -> usize {
    w.events().iter().filter(|e| *e == "h.off").count()
}

/// The force stop returns once the job is queued; the reaper waits (bounded)
/// for the unit to go inactive and then runs after_off.
#[test]
fn unit_force_stop_waits_for_the_queued_job() {
    let w = World::new();
    let (v, h) = queued_vmm(&w, Duration::from_secs(1));
    v.boot(&h).unwrap();
    v.stop(&h).unwrap();
    // the ladder takes power_s + shutdown_s + the queued job: destroy is
    // bounded (R41), so it is retried as the manager's tick does
    destroy_eventually(&v, &h).unwrap();
    assert_eq!(offs(&w), 1, "{:?}", w.events());
}

/// A unit that goes inactive only after the bound: destroy fails (the exit
/// is unconfirmed, the dir is kept), and once it is gone the next status
/// confirms it and runs after_off exactly once.
#[test]
fn a_late_exit_still_gets_after_off_once() {
    let w = World::new();
    let (v, h) = queued_vmm(&w, Duration::from_secs(5));
    v.boot(&h).unwrap();
    v.stop(&h).unwrap();
    assert!(v.destroy(&h).is_err());
    assert!(
        w.paths("b1").vm_json().exists(),
        "an unconfirmed exit keeps the runtime dir"
    );
    assert_eq!(offs(&w), 0, "{:?}", w.events());
    assert!(wait_for(LONG, || matches!(
        v.status(&h),
        VmStatus::Off | VmStatus::Gone
    )));
    assert!(wait_for(Duration::from_secs(2), || offs(&w) == 1));
    let _ = v.status(&h);
    v.stop(&h).unwrap();
    v.destroy(&h).unwrap();
    assert_eq!(offs(&w), 1, "{:?}", w.events());
}

/// R41: destroy is bounded to about a second. A VMM that ignores the power
/// button is still stopping: destroy fails at once and keeps everything
/// (runtime dir, pid record); once the ladder ends, a retried destroy
/// succeeds and the runtime dir goes.
#[test]
fn destroy_is_bounded_and_a_retry_finishes_it() {
    let w = World::new();
    let l = w.launcher(&[("FAKE_CH_IGNORE_POWER", "1")]);
    let stop = StopTimes {
        power_s: 3,
        shutdown_s: 2,
        force_s: 2,
    };
    let v = w.vmm_times(
        Arc::clone(&l),
        vec![w.hook("h", false)],
        rustix::process::geteuid().as_raw(),
        stop,
    );
    let h = w.create(&v, "b1");
    v.boot(&h).unwrap();
    let t = Instant::now();
    let m = failed(v.destroy(&h));
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    assert!(m.contains("still stopping"), "{m}");
    assert!(w.paths("b1").vm_json().exists(), "the runtime dir is kept");
    assert!(w.pid_record("b1").exists(), "the pid record is kept");
    assert_eq!(l.exited(&h.id), Some(false), "the VMM still runs");
    assert_eq!(offs(&w), 0, "{:?}", w.events());
    // a second call is bounded too and still keeps everything
    let t = Instant::now();
    assert!(v.destroy(&h).is_err());
    assert!(t.elapsed() < Duration::from_millis(1500));
    assert!(w.paths("b1").vm_json().exists());
    // the ladder ends (vmm.shutdown after power_s): the next destroy succeeds
    assert!(wait_for(LONG, || l.exit_status(&h.id).is_some()));
    v.destroy(&h).unwrap();
    assert!(!w.paths("b1").dir.exists(), "the runtime dir is gone");
    assert!(!w.pid_record("b1").exists());
    assert_eq!(offs(&w), 1, "{:?}", w.events());
    assert_eq!(v.status(&h), VmStatus::Gone);
}

/// R41: a destroy during a boot does not wait out the boot either.
#[test]
fn destroy_during_a_slow_boot_is_bounded() {
    let w = World::new();
    let l = w.launcher(&[]);
    let v = w.vmm_with(l, vec![w.slow_hook("h", false, Duration::from_secs(3))]);
    let h = w.create(&v, "b1");
    std::thread::scope(|s| {
        let a = s.spawn(|| v.boot(&h));
        std::thread::sleep(Duration::from_millis(100));
        let t = Instant::now();
        let m = failed(v.destroy(&h));
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t.elapsed()
        );
        assert!(m.contains("booting"), "{m}");
        a.join().unwrap().unwrap();
    });
    destroy_eventually(&v, &h).unwrap();
    assert!(!w.paths("b1").dir.exists());
}

/// The real-path manager (plan 35 R40, plan 37): the store at the record
/// root, `ChVmm` on the fake CH and the daemon's placer
/// (`layout::record_disk_place`). A spawn with a repo disk is admitted and
/// booted, never `Unavailable`; the disk ends in the runtime dir, where the
/// VMM is told to open it, and the base manifest stays in the record.
#[test]
fn a_spawn_with_a_repo_disk_on_the_real_path_manager_boots() {
    use saiife_boxes::capacity::HostFacts;
    use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
    use saiife_boxes::store::Store;
    use saiife_boxhost::paths::{BASE_MANIFEST, REPO_DISK};
    use saiife_wire::source::{BoxState, Start};
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let inc = w.records.join(".incoming").join("0123456789abcdef");
    std::fs::create_dir_all(&inc).unwrap();
    std::fs::set_permissions(
        w.records.join(".incoming"),
        PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(inc.join(REPO_DISK), b"repo").unwrap();
    std::fs::write(inc.join(BASE_MANIFEST), b"{}").unwrap();
    let m = Manager::open(ManagerInit {
        store: Store::open(w.records.clone()).unwrap(),
        vmm: Arc::clone(&v) as Arc<dyn Vmm>,
        guest: Arc::new(saiife_boxes::guest::NoGuest),
        templates: saiife_boxes::template::builtin(),
        host: Arc::new(|| HostFacts {
            mem_total_mib: 64 << 10,
            mem_avail_mib: 64 << 10,
            threads: 32,
            disk_free_mib: 1 << 20,
            cpu_pct: None,
        }),
        clock: Arc::new(|| 1_700_000_000),
        disk_place: Some(Arc::new(|root: &Path, id: &BoxId| {
            saiife_boxhost::layout::record_disk_place(root, id)
        })),
    })
    .unwrap()
    .manager;
    let r = m
        .spawn(&SpawnArgs {
            template: "claude-code".into(),
            repo: "shop".into(),
            repo_dir: None,
            task: "t".into(),
            start: Start::Now,
            owner_uid: 1000,
            repo_image: Some(inc.join(REPO_DISK)),
            base_manifest: Some(inc.join(BASE_MANIFEST)),
        })
        .expect("a spawn with a repo disk is admitted");
    if let Some(h) = &r.vm {
        w.track(&v, h);
    }
    assert_eq!(r.state, BoxState::Starting, "{r:?}");
    let id = r.id.as_str();
    let rec = w.records.join(id);
    assert!(
        rec.join(BASE_MANIFEST).exists(),
        "base.json stays in the record"
    );
    assert!(!rec.join(REPO_DISK).exists(), "the disk left the record");
    let p = w.paths(id);
    assert_eq!(std::fs::read(p.repo_disk()).unwrap(), b"repo");
    assert!(!p.dir.join(BASE_MANIFEST).exists());
    assert!(read_spec(&p).unwrap().repo, "the VMM is told to open it");
}

/// The fake CH's argv of box `id`'s last start.
fn ch_argv(w: &World, id: &str) -> Vec<String> {
    std::fs::read_to_string(w.paths(id).dir.join("fake-ch.argv"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// vm.json is in the runtime dir, which the VMM user can write (R37): a
/// VMM that edits it between runs (Landlock off, four times the memory,
/// more vCPUs, its own kernel) gets none of it. Boot builds the spec from
/// the daemon's own state (the handle in the box record, the image store,
/// the driver's Landlock setting) and writes it fresh.
#[test]
fn a_tampered_vm_json_is_never_trusted_at_boot() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let p = w.paths("b1");
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p.vm_json()).unwrap()).unwrap();
    s["landlock"] = false.into();
    s["mem_mib"] = (4096u64 * 4).into();
    s["vcpus"] = 32.into();
    s["boot"] = serde_json::json!({"kernel": {
        "kernel": w.root.join("i/base").display().to_string(),
        "cmdline": "init=/bin/sh"}});
    std::fs::write(p.vm_json(), s.to_string()).unwrap();
    v.boot(&h).unwrap();
    let a = ch_argv(&w, "b1");
    assert!(a.iter().any(|x| x == "--landlock"), "{a:?}");
    assert!(a.iter().any(|x| x == "size=4096M"), "{a:?}");
    assert!(a.iter().any(|x| x == "boot=2"), "{a:?}");
    assert!(a.iter().any(|x| x == "--firmware"), "{a:?}");
    assert!(
        !a.iter().any(|x| x == "--kernel" || x.contains("init=")),
        "{a:?}"
    );
    // and the file now says what was booted
    let s = read_spec(&p).unwrap();
    assert!(s.landlock && s.mem_mib == 4096 && s.vcpus == 2);
}

/// A handle without the sizes boot needs (one made before they were kept
/// in the record) is refused rather than read from vm.json.
#[test]
fn a_handle_without_its_sizes_does_not_boot() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let old = VmHandle {
        data: serde_json::json!({"launcher": "child", "image": format!("base-{HEX}")}).to_string(),
        ..h.clone()
    };
    let e = failed(v.boot(&old));
    assert!(e.contains("record"), "{e}");
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
}

/// A snapshot's config.json is the VMM's own (sealed, but written by
/// it): on restore Cloud Hypervisor takes the vCPUs and memory from it,
/// not from argv. More vCPUs, more memory, hotplug, shared or hugepage
/// memory than the box was admitted with are refused; the box boots cold.
#[test]
fn restore_refuses_sizes_the_box_was_not_admitted_with() {
    type Edit = fn(&mut serde_json::Value);
    let edits: &[(&str, Edit)] = &[
        ("vcpus", |c| c["cpus"]["boot_vcpus"] = 32.into()),
        ("max vcpus", |c| c["cpus"]["max_vcpus"] = 32.into()),
        ("memory", |c| {
            c["memory"]["size"] = ((4096u64 * 4) << 20).into()
        }),
        ("hotplug", |c| {
            c["memory"]["hotplug_size"] = (1u64 << 34).into()
        }),
        ("shared", |c| c["memory"]["shared"] = true.into()),
        ("hugepages", |c| c["memory"]["hugepages"] = true.into()),
    ];
    for (what, edit) in edits {
        let w = World::new();
        let (v, _l) = w.vmm(&[]);
        let h = w.snapshotted(&v, "b1");
        w.forge("b1", edit);
        v.boot(&h).unwrap();
        assert!(w.booted_cold("b1"), "{what}");
        assert!(
            w.events().contains(&"h.refused".to_string()),
            "{what}: {:?}",
            w.events()
        );
    }
}

/// Whether a box has a repo disk is the daemon's record, not what the
/// VMM-writable runtime dir holds at boot: a repo.img planted there for
/// a box created without one is refused.
#[test]
fn boot_refuses_a_repo_disk_the_box_was_not_created_with() {
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    std::fs::write(w.paths("b1").repo_disk(), b"planted").unwrap();
    let e = failed(v.boot(&h));
    assert!(e.contains("repo"), "{e}");
    assert!(!w.paths("b1").dir.join("fake-ch.argv").exists());
}

/// state.json is the VMM's own too: on restore Cloud Hypervisor rebuilds
/// the vCPUs and the guest RAM from it. More vCPU states, more RAM, a
/// hotplug slot in use or a state that cannot be read (all re-signed, as
/// a VMM that forged them before the seal would have them) are refused
/// with an audit hook call; the box boots cold.
#[test]
fn restore_refuses_a_state_the_box_was_not_admitted_with() {
    type Edit = fn(&mut serde_json::Value) -> Vec<u8>;
    fn mem(v: &mut serde_json::Value, f: fn(&mut serde_json::Value)) -> Vec<u8> {
        let p = "/snapshots/memory-manager/snapshot_data/state";
        let mut m: serde_json::Value =
            serde_json::from_str(v.pointer(p).unwrap().as_str().unwrap()).unwrap();
        f(&mut m);
        *v.pointer_mut(p).unwrap() = m.to_string().into();
        serde_json::to_vec(v).unwrap()
    }
    let edits: &[(&str, Edit)] = &[
        ("vcpus", |v| {
            v["snapshots"]["cpu-manager"]["snapshots"]["9"] = serde_json::json!({});
            serde_json::to_vec(v).unwrap()
        }),
        ("ram", |v| {
            mem(v, |m| {
                m["boot_ram"] = (1u64 << 36).into();
                m["current_ram"] = (1u64 << 36).into();
                m["guest_ram_mappings"][0]["size"] = (1u64 << 36).into();
            })
        }),
        ("hotplug", |v| {
            mem(v, |m| m["hotplug_slots"][0]["active"] = true.into())
        }),
        ("unparseable", |_| b"{\"snapshots\": [".to_vec()),
        ("empty", |_| b"{}".to_vec()),
    ];
    for (what, edit) in edits {
        let w = World::new();
        let (v, _l) = w.vmm(&[]);
        let h = w.snapshotted(&v, "b1");
        w.forge_state("b1", edit);
        v.boot(&h).unwrap();
        assert!(w.booted_cold("b1"), "{what}");
        assert!(
            w.events().contains(&"h.refused".to_string()),
            "{what}: {:?}",
            w.events()
        );
        assert!(!w.marker("b1").exists() && !w.snap("b1").exists(), "{what}");
    }
}

/// Locked: create records the smallest size tier that holds the box, and
/// boot starts that tier's unit (`saiife-box-<tier>@<id>`), whose fixed
/// caps the installer wrote. A record without a tier is refused, not
/// started under a guessed unit.
#[test]
fn unit_boot_starts_the_recorded_tier_unit() {
    let w = World::new();
    let bus = Arc::new(QueuedStopBus {
        fake: FakeUnitBus::new(),
        child: w.launcher(&[]),
        paths: w.paths("b1"),
        id: BoxId::parse("b1").unwrap(),
        delay: Duration::from_millis(10),
        active: Arc::new(Mutex::new(false)),
    });
    let v = w.vmm_with(
        Arc::new(UnitLauncher::new(bus.clone())),
        vec![w.hook("h", false)],
    );
    let mut spec = w.spec("b1");
    spec.size.vcpus = 3; // 3 vCPUs, 4 GiB: tier l (4 vCPUs, 8 GiB)
    let h = v.create(&spec).unwrap();
    w.track(&v, &h);
    let data: serde_json::Value = serde_json::from_str(&h.data).unwrap();
    assert_eq!(data["tier"], "l");
    v.boot(&h).unwrap();
    let calls = bus.fake.calls.lock().unwrap().clone();
    assert!(
        calls.iter().any(|c| c == "start saiife-box-l@b1.service"),
        "{calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.contains("saiife-box@")),
        "{calls:?}"
    );

    // a handle without a tier (an older record): refused, nothing started
    let w = World::new();
    let (v0, _l) = w.vmm(&[]);
    let h = w.create(&v0, "b1");
    let mut data: serde_json::Value = serde_json::from_str(&h.data).unwrap();
    data.as_object_mut().unwrap().remove("tier");
    let old = VmHandle {
        data: data.to_string(),
        ..h
    };
    let bus = Arc::new(FakeUnitBus::new());
    let v = w.vmm_with(Arc::new(UnitLauncher::new(bus.clone())), vec![]);
    let m = failed(v.boot(&old));
    assert!(
        m.contains("no size tier") && m.contains("spawn it again"),
        "{m}"
    );
    assert!(!bus
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("start")));
    // ... and, with no unit of it running, it can be discarded as told
    v.destroy(&old).unwrap();

    // a tier smaller than the record's own sizes is not trusted
    let w = World::new();
    let (v, _l) = w.vmm(&[]);
    let h = w.create(&v, "b1");
    let mut data: serde_json::Value = serde_json::from_str(&h.data).unwrap();
    data["tier"] = "s".into(); // 1 vCPU, 2 GiB; the box has 2 and 4 GiB
    let small = VmHandle {
        data: data.to_string(),
        ..h
    };
    assert!(failed(v.boot(&small)).contains("no size tier"));
}
