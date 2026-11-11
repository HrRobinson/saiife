//! A box manager on fakes, shared by the manager and conformance tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::GuestLink;
use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
use saiife_boxes::store::{BoxRecord, Store};
use saiife_boxes::template::{self, BoxTemplate, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::BoxId;
use saiife_wire::source::Start;

/// The clock's starting point, in Unix seconds.
pub const T0: u64 = 1_000_000;

pub struct World {
    pub mgr: Arc<Manager>,
    pub vmm: Arc<FakeVmm>,
    pub guest: Arc<FakeGuest>,
    pub clock: Arc<AtomicU64>,
    pub host: HostFacts,
    pub templates: Vec<BoxTemplate>,
    /// The store root (`<tempdir>/boxes`).
    pub root: PathBuf,
    pub dir: tempfile::TempDir,
}

/// A host that holds exactly `n` default boxes (memory bound; 12 threads).
pub fn host(n: u32) -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + u64::from(n) * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

pub fn world(n: u32) -> World {
    world_with(n, Vec::new())
}

/// `world(n)` with `extra` templates after the built-in ones.
pub fn world_with(n: u32, extra: Vec<BoxTemplate>) -> World {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("boxes");
    let mut templates = template::builtin();
    templates.extend(extra);
    let vmm = Arc::new(FakeVmm::new());
    let guest = Arc::new(FakeGuest::new());
    let clock = Arc::new(AtomicU64::new(T0));
    let host = host(n);
    let g: Arc<dyn GuestLink> = guest.clone();
    let init = make_init(&root, &vmm, g, &templates, host, &clock);
    let (mgr, warns) = Manager::open(init).unwrap();
    assert!(warns.is_empty(), "{warns:?}");
    World {
        mgr: Arc::new(mgr),
        vmm,
        guest,
        clock,
        host,
        templates,
        root,
        dir,
    }
}

fn make_init(
    root: &Path,
    vmm: &Arc<FakeVmm>,
    guest: Arc<dyn GuestLink>,
    templates: &[BoxTemplate],
    host: HostFacts,
    clock: &Arc<AtomicU64>,
) -> ManagerInit {
    let clock = clock.clone();
    ManagerInit {
        store: Store::open(root.to_path_buf()).unwrap(),
        vmm: vmm.clone(),
        guest,
        templates: templates.to_vec(),
        host: Arc::new(move || host),
        clock: Arc::new(move || clock.load(Ordering::SeqCst)),
    }
}

/// A sized copy of the built-in template under another name.
pub fn template_sized(name: &str, size: Size) -> BoxTemplate {
    let mut t = template::builtin().remove(0);
    t.name = name.into();
    t.size = size;
    t
}

pub fn id(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

impl World {
    /// A fresh `ManagerInit` over this world's store, VMM, host and clock.
    pub fn init(&self, guest: Arc<dyn GuestLink>) -> ManagerInit {
        make_init(
            &self.root,
            &self.vmm,
            guest,
            &self.templates,
            self.host,
            &self.clock,
        )
    }

    /// Simulate a daemon restart: a new manager over the same store and VMM.
    pub fn reopen(&mut self) -> Vec<String> {
        let guest: Arc<dyn GuestLink> = self.guest.clone();
        let (mgr, warns) = Manager::open(self.init(guest)).unwrap();
        self.mgr = Arc::new(mgr);
        warns
    }

    pub fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn args(&self, template: &str, task: &str, start: Start) -> SpawnArgs {
        SpawnArgs {
            template: template.into(),
            repo: "shop".into(),
            repo_dir: None,
            task: task.into(),
            start,
            owner_uid: 1000,
            repo_image: None,
            base_manifest: None,
        }
    }

    /// Spawn a built-in box with `task`, joining the queue.
    pub fn spawn(&self, task: &str) -> BoxRecord {
        self.mgr
            .spawn(&self.args("claude-code", task, Start::Queue))
            .unwrap()
    }

    /// The record as saved on disk.
    pub fn on_disk(&self, i: &BoxId) -> Option<BoxRecord> {
        Store::open(self.root.clone()).unwrap().load(i).unwrap()
    }

    /// Assert the in-memory record is the one on disk.
    pub fn assert_saved(&self, i: &BoxId) {
        assert_eq!(self.on_disk(i), Some(self.mgr.get(i).unwrap()), "{i:?}");
    }
}
