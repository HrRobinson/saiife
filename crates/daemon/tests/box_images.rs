//! The `box.image.*` ops (plan 36, Task 5) over a box manager on `FakeVmm`:
//! the image store split into a records dir and an images dir, import over
//! passed descriptors, the admin check, the audit records, `rm` refusals
//! and the image named at admission. No VM is ever started.
#![cfg(all(unix, feature = "fake-vmm"))]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::{GuestEvent, GuestLink};
use saiife_boxes::manager::{Manager, ManagerInit};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, Size};
use saiife_boxes::vmm::fake::{FakeVmm, VmOp};
use saiife_boxes::BoxId;
use saiife_boxhost::image::ubuntu::UBUNTU_CLOUD_FPR;
use saiife_boxhost::image::{
    image_id, Manifest, ManifestBoot, ManifestPin, ManifestUbuntu, ManifestVmm,
};
use saiife_boxhost::pins::sha256_file;
use saiife_daemon::box_images::ImagePaths;
use saiife_daemon::box_ops;
use saiife_daemon::ops::{dispatch, dispatch_conn, Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync};
use serde_json::{json, Value};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const ALICE: u32 = 2000;
/// In `[admin] groups` (`admins`).
const CAROL: u32 = 2002;
const ROOT: u32 = 0;

const UNAVAILABLE_WHY: &str = "boxes are unavailable: no default box image";

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

/// A valid firmware-boot manifest for an image with digest `sha`.
fn manifest_for(sha: &str) -> Manifest {
    Manifest {
        version: 1,
        id: image_id(sha),
        sha256: sha.to_string(),
        virtual_gib: 20,
        actual_bytes: 1234,
        built_at: "2026-01-01T00:00:00Z".into(),
        builder: "saiife 0.0.0".into(),
        recipe_sha256: hex('d'),
        ubuntu: ManifestUbuntu {
            release: "release-20261017".into(),
            image_sha256: hex('e'),
            sums_signer: UBUNTU_CLOUD_FPR.into(),
        },
        vmm: ManifestVmm {
            ch_version: "v0".into(),
            ch_sha256: hex('1'),
            fw_version: "v0".into(),
            fw_sha256: hex('2'),
        },
        saiife: ManifestPin {
            version: "0.0.0".into(),
            sha256: hex('3'),
        },
        claude: ManifestPin {
            version: "9.9.9".into(),
            sha256: hex('4'),
        },
        agents: Default::default(),
        packages: Vec::new(),
        images: Vec::new(),
        boot: ManifestBoot::Firmware,
        signature: None,
    }
}

struct World {
    ctx: Arc<Ctx>,
    mgr: Arc<Manager>,
    vmm: Arc<FakeVmm>,
    guest: Arc<FakeGuest>,
    audit: PathBuf,
    paths: ImagePaths,
    tmp: tempfile::TempDir,
}

/// A host that holds exactly `n` default boxes.
fn host(n: u64) -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + n * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

/// A daemon context in `mode` with a two-box manager and an image store
/// in the temp dir. Locked: the daemon is uid 999, `carol` is an admin.
/// Personal: the daemon is this process's uid.
fn world(mode: Mode) -> World {
    world_with(mode, true)
}

/// `manager: false`: a daemon whose box preflight failed (no manager), as
/// one without a default image yet starts.
fn world_with(mode: Mode, manager: bool) -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> =
        Arc::new(saiife_policy::FixedDirectory::from_text(
            "root:x:0:0::/root:/bin/sh\n\
         saiife:x:999:999::/var/lib/saiife:/bin/sh\n\
         alice:x:2000:2000::/home/alice:/bin/sh\n\
         carol:x:2002:2002::/home/carol:/bin/sh\n",
            "admins:x:3000:carol\n",
        ));
    let vmm = Arc::new(FakeVmm::new());
    let guest = Arc::new(FakeGuest::new());
    let g: Arc<dyn GuestLink> = guest.clone();
    let h = host(2);
    let o = Manager::open(ManagerInit {
        store: Store::open(box_ops::dir_in(&state)).unwrap(),
        vmm: vmm.clone(),
        guest: g,
        templates: template::builtin(),
        host: Arc::new(move || h),
        clock: Arc::new(|| 1_000_000),
        disk_place: box_ops::disk_place(),
    })
    .unwrap();
    let mgr = Arc::new(o.manager);
    let paths = ImagePaths {
        records: tmp.path().join("records"),
        images: tmp.path().join("images"),
    };
    let own_uid = match mode {
        Mode::Locked => 999,
        Mode::Personal => rustix::process::getuid().as_raw(),
    };
    let base = CtxInit::minimal(handle, cfg, dirs, &state);
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        own_uid,
        mode,
        socket_dir: tmp.path().join("run"),
        policy: PolicyState {
            admin_groups: vec!["admins".into()],
            ..PolicyState::invalid(0)
        },
        box_manager: manager.then(|| Arc::clone(&mgr)),
        box_unavailable: (!manager).then(|| UNAVAILABLE_WHY.to_string()),
        box_images: Some(paths.clone()),
        ..base
    }));
    World {
        ctx,
        mgr,
        vmm,
        guest,
        audit,
        paths,
        tmp,
    }
}

fn peer(uid: u32) -> PeerCred {
    PeerCred {
        uid,
        gid: uid,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

fn id(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

/// A source image: `content` at `<tmp>/<name>.raw`, and its manifest.
struct Src {
    raw: PathBuf,
    manifest: Manifest,
}

impl World {
    fn src(&self, name: &str, content: &str) -> Src {
        let raw = self.tmp.path().join(format!("{name}.raw"));
        std::fs::write(&raw, content).unwrap();
        let manifest = manifest_for(&sha256_file(&raw).unwrap());
        Src { raw, manifest }
    }

    async fn call(&self, uid: u32, op: &str, args: Value) -> Value {
        self.call_passing(uid, op, args, Vec::new()).await
    }

    /// `op` on a connection that was passed `fds`.
    async fn call_passing(&self, uid: u32, op: &str, args: Value, fds: Vec<OwnedFd>) -> Value {
        let req = Request {
            id: 7,
            op: op.into(),
            args: args.as_object().cloned().unwrap_or_default(),
        };
        if fds.is_empty() {
            return dispatch(&self.ctx, &peer(uid), req).await;
        }
        let conn = Conn::new(peer(uid), None);
        *conn.fds.lock().unwrap() = fds;
        let a = dispatch_conn(&self.ctx, &conn, req).await;
        assert!(conn.take_fds().is_empty(), "the stash was taken");
        a
    }

    async fn import(&self, uid: u32, s: &Src, default: bool) -> Value {
        let fd: OwnedFd = File::open(&s.raw).unwrap().into();
        self.call_passing(
            uid,
            "box.image.import",
            json!({"manifest": serde_json::to_value(&s.manifest).unwrap(), "default": default}),
            vec![fd],
        )
        .await
    }

    async fn imported(&self, uid: u32, s: &Src, default: bool) {
        let a = self.import(uid, s, default).await;
        assert_eq!(a["ok"], true, "{a}");
        assert_eq!(a["image"], s.manifest.id.as_str(), "{a}");
    }

    async fn ok(&self, uid: u32, op: &str, args: Value) -> Value {
        let a = self.call(uid, op, args).await;
        assert_eq!(a["ok"], true, "{op}: {a}");
        a
    }

    /// Every name in the records dir (`r/`), the images dir (`i/`) and
    /// `.incoming` (`inc/`).
    fn store_names(&self) -> Vec<String> {
        let ls = |d: &Path, pre: &str| -> Vec<String> {
            match std::fs::read_dir(d) {
                Ok(rd) => rd
                    .map(|e| format!("{pre}{}", e.unwrap().file_name().to_string_lossy()))
                    .collect(),
                Err(_) => Vec::new(),
            }
        };
        let mut v = ls(&self.paths.records, "r/");
        v.extend(
            ls(&self.paths.images, "i/")
                .into_iter()
                .filter(|n| n != "i/.incoming"),
        );
        v.extend(ls(&self.paths.images.join(".incoming"), "inc/"));
        v.sort();
        v
    }

    /// The `box` records written so far.
    fn records(&self) -> Vec<Value> {
        let mut files: Vec<_> = std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap())
                    .collect::<Vec<_>>()
            })
            .filter(|r| r["kind"] == "box")
            .collect()
    }

    fn image_records(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| {
                r["action"]
                    .as_str()
                    .is_some_and(|a| a.starts_with("image_"))
            })
            .collect()
    }

    async fn spawn(&self, uid: u32) -> Value {
        let a = self
            .ok(
                uid,
                "box.spawn",
                json!({"template": "claude-code", "repo": "shop", "task": "t", "start": "queue"}),
            )
            .await;
        a["box"].clone()
    }
}

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[tokio::test]
async fn import_checks_sha256() {
    let w = world(Mode::Personal);
    let s = w.src("a", "image-a\n");
    let mut bad = manifest_for(&hex('0'));
    bad.boot = ManifestBoot::Firmware;
    let lie = Src {
        raw: s.raw.clone(),
        manifest: bad,
    };
    let a = w.import(me(), &lie, false).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "bad_request", "{a}");
    let msg = a["message"].as_str().unwrap();
    assert!(
        msg.contains("sha256") && msg.contains(&s.manifest.sha256),
        "{msg}"
    );
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
    assert!(w.image_records().is_empty());

    w.imported(me(), &s, false).await;
    let i = &s.manifest.id;
    assert_eq!(
        w.store_names(),
        vec![format!("i/{i}.raw"), format!("r/{i}.json")]
    );
    let raw = w.paths.images.join(format!("{i}.raw"));
    assert_eq!(std::fs::read_to_string(&raw).unwrap(), "image-a\n");
    assert_eq!(mode_of(&raw), 0o440);
    assert_eq!(mode_of(&w.paths.records), 0o700);
    assert_eq!(mode_of(&w.paths.images.join(".incoming")), 0o700);
    // The daemon's copy is checked, not the sender's file afterwards: the
    // same image again is refused as already there.
    let a = w.import(me(), &s, false).await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a["message"].as_str().unwrap().contains("already"), "{a}");
}

/// A kernel-booting image takes the raw disk and its kernel; the kernel
/// is checked against `boot.sha256` too.
#[tokio::test]
async fn import_with_kernel() {
    let w = world(Mode::Personal);
    let mut s = w.src("k", "image-k\n");
    let k = w.tmp.path().join("k.vmlinuz");
    std::fs::write(&k, "kernel").unwrap();
    s.manifest.boot = ManifestBoot::Kernel {
        kernel: format!("{}.vmlinuz", s.manifest.id),
        sha256: sha256_file(&k).unwrap(),
        cmdline: "console=ttyS0".into(),
    };
    let args = json!({"manifest": serde_json::to_value(&s.manifest).unwrap()});
    let fds = |kernel: &Path| -> Vec<OwnedFd> {
        vec![
            File::open(&s.raw).unwrap().into(),
            File::open(kernel).unwrap().into(),
        ]
    };
    let other = w.tmp.path().join("other.vmlinuz");
    std::fs::write(&other, "another kernel").unwrap();
    let a = w
        .call_passing(me(), "box.image.import", args.clone(), fds(&other))
        .await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("kernel's sha256"),
        "{a}"
    );
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
    let a = w
        .call_passing(me(), "box.image.import", args, fds(&k))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    let kp = w.paths.images.join(format!("{}.vmlinuz", s.manifest.id));
    assert_eq!(std::fs::read_to_string(&kp).unwrap(), "kernel");
    assert_eq!(mode_of(&kp), 0o440);
}

/// The CLI opens its files `O_NOFOLLOW`; the daemon refuses any
/// descriptor that is not a regular file, a symlink itself included.
#[tokio::test]
async fn import_refuses_a_symlink_fd_target() {
    use rustix::fs::{Mode as FMode, OFlags};
    let w = world(Mode::Personal);
    let s = w.src("a", "image-a\n");
    let link = w.tmp.path().join("link.raw");
    std::os::unix::fs::symlink(&s.raw, &link).unwrap();
    // The CLI's open of the link fails.
    let e = rustix::fs::open(
        &link,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FMode::empty(),
    )
    .unwrap_err();
    assert_eq!(e, rustix::io::Errno::LOOP);
    // A descriptor of the link itself, or of a dir, is refused.
    let at_link = rustix::fs::open(
        &link,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FMode::empty(),
    )
    .unwrap();
    let dir: OwnedFd = File::open(w.tmp.path()).unwrap().into();
    let args = json!({"manifest": serde_json::to_value(&s.manifest).unwrap()});
    for fd in [at_link, dir] {
        let a = w
            .call_passing(me(), "box.image.import", args.clone(), vec![fd])
            .await;
        assert_eq!(a["ok"], false, "{a}");
        assert!(
            a["message"]
                .as_str()
                .unwrap()
                .contains("not a regular file"),
            "{a}"
        );
    }
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
}

#[tokio::test]
async fn import_refuses_bad_manifest() {
    let w = world(Mode::Personal);
    let s = w.src("a", "image-a\n");
    let good = serde_json::to_value(&s.manifest).unwrap();
    let mut unknown = good.clone();
    unknown["extra"] = json!(1);
    let mut bad_id = good.clone();
    bad_id["id"] = json!("base-nope");
    let mut kernel = good.clone();
    kernel["boot"] = json!({"kernel": {
        "kernel": format!("{}.vmlinuz", s.manifest.id),
        "sha256": hex('6'),
        "cmdline": "console=ttyS0",
    }});
    let cases = [
        (json!({}), "manifest"),
        (json!({"manifest": "text"}), "manifest"),
        (json!({"manifest": unknown}), "unknown field"),
        (json!({"manifest": bad_id}), "id"),
        (
            json!({"manifest": good.clone(), "default": "yes"}),
            "default",
        ),
        // The manifest boots a kernel: two descriptors, not one.
        (json!({"manifest": kernel}), "descriptor"),
    ];
    for (args, want) in cases {
        let fd: OwnedFd = File::open(&s.raw).unwrap().into();
        let a = w
            .call_passing(me(), "box.image.import", args.clone(), vec![fd])
            .await;
        assert_eq!(a["ok"], false, "{args}: {a}");
        assert_eq!(a["error"], "bad_request", "{a}");
        assert!(a["message"].as_str().unwrap().contains(want), "{want}: {a}");
    }
    // A firmware image with a kernel descriptor too, and none at all.
    let two: Vec<OwnedFd> = vec![
        File::open(&s.raw).unwrap().into(),
        File::open(&s.raw).unwrap().into(),
    ];
    let args = json!({"manifest": good});
    for fds in [two, Vec::new()] {
        let a = w
            .call_passing(me(), "box.image.import", args.clone(), fds)
            .await;
        assert_eq!(a["ok"], false, "{a}");
        assert!(a["message"].as_str().unwrap().contains("descriptor"), "{a}");
    }
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
    assert!(w.image_records().is_empty());
}

#[tokio::test]
async fn import_is_admin_only_locked() {
    let w = world(Mode::Locked);
    let s = w.src("a", "image-a\n");
    let a = w.import(ALICE, &s, false).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden", "{a}");
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
    w.imported(ROOT, &s, false).await;
    let b = w.src("b", "image-b\n");
    w.imported(CAROL, &b, false).await;
    // default and rm are admin-only too; ls is open.
    let img = json!({"image": s.manifest.id});
    for op in ["box.image.default", "box.image.rm"] {
        let a = w.call(ALICE, op, img.clone()).await;
        assert_eq!(a["error"], "forbidden", "{op}: {a}");
    }
    let a = w.ok(ALICE, "box.image.ls", json!({})).await;
    assert_eq!(a["images"].as_array().unwrap().len(), 2, "{a}");
    // Personal: the daemon's own user may.
    let p = world(Mode::Personal);
    let s = p.src("a", "image-a\n");
    let a = p.import(ALICE, &s, false).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    p.imported(me(), &s, false).await;
}

#[tokio::test]
async fn import_writes_one_record_with_sha256() {
    let w = world(Mode::Locked);
    let s = w.src("a", "image-a\n");
    w.imported(ROOT, &s, false).await;
    let recs = w.image_records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["action"], "image_import");
    assert_eq!(r["box"], Value::Null);
    assert_eq!(r["template"], Value::Null);
    assert_eq!(r["from"], Value::Null);
    assert_eq!(r["to"], Value::Null);
    assert_eq!(r["via"], "cli");
    assert_eq!(r["image"], s.manifest.id.as_str());
    assert_eq!(r["sha256"], s.manifest.sha256.as_str());
    assert_eq!(r["signed"], false);
    assert_eq!(r["ubuntu"], hex('e'));
    assert_eq!(r["claude"], "9.9.9");
    assert_eq!(r["uid"], 0);
    // `--default`: one record more.
    let b = w.src("b", "image-b\n");
    w.imported(ROOT, &b, true).await;
    let recs = w.image_records();
    let actions: Vec<&str> = recs.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["image_import", "image_import", "image_default"]);
    assert_eq!(recs[2]["image"], b.manifest.id.as_str());
    assert_eq!(recs[2]["sha256"], b.manifest.sha256.as_str());
    let a = w.ok(ROOT, "box.image.ls", json!({})).await;
    let def: Vec<&Value> = a["images"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["default"] == true)
        .collect();
    assert_eq!(def.len(), 1);
    assert_eq!(def[0]["id"], b.manifest.id.as_str());
}

#[tokio::test]
async fn default_and_ls() {
    let w = world(Mode::Personal);
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert_eq!(a["images"], json!([]));
    assert_eq!(a["warnings"], json!([]));
    let s = w.src("a", "image-a\n");
    let b = w.src("b", "image-b\n");
    w.imported(me(), &s, false).await;
    w.imported(me(), &b, false).await;
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert!(a["images"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["default"] == false && i["in_use"] == json!([])));
    w.ok(me(), "box.image.default", json!({"image": b.manifest.id}))
        .await;
    assert_eq!(
        std::fs::read_to_string(w.paths.records.join("default")).unwrap(),
        format!("{}\n", b.manifest.id)
    );
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    let images = a["images"].as_array().unwrap();
    assert_eq!(images.len(), 2);
    for i in images {
        let want = i["id"] == b.manifest.id.as_str();
        assert_eq!(i["default"], want, "{i}");
        assert_eq!(i["ubuntu"]["release"], "release-20261017");
        assert_eq!(i["claude"]["version"], "9.9.9");
    }
    let recs = w.image_records();
    assert_eq!(recs.last().unwrap()["action"], "image_default");
    // A default that is not in the store, or not an id, is refused.
    let a = w
        .call(
            me(),
            "box.image.default",
            json!({"image": image_id(&hex('9'))}),
        )
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    let a = w
        .call(me(), "box.image.default", json!({"image": "../etc"}))
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    // A broken manifest in the records dir is a warning.
    std::fs::write(
        w.paths
            .records
            .join(format!("{}.json", image_id(&hex('f')))),
        "{",
    )
    .unwrap();
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert_eq!(a["warnings"].as_array().unwrap().len(), 1, "{a}");
}

/// Over a real control socket through `Client::call`: `default` and `rm`
/// take `{image}`; an `id` key is the request's own and names nothing;
/// the answer of `import` has `image`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_and_rm_take_image_not_id() {
    use saiife_ipc::client::{Client, ClientError};
    use serde_json::Map;
    use std::os::fd::AsFd;
    use std::time::Instant;
    let w = world(Mode::Personal);
    let run = w.tmp.path().join("run");
    std::fs::create_dir(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = tokio::net::UnixListener::bind(run.join(saiife_ipc::msg::SOCKET_NAME)).unwrap();
    let ctx = Arc::clone(&w.ctx);
    let server = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&ctx)));
        }
    });
    let a = w.src("a", "image-a\n");
    let b = w.src("b", "image-b\n");
    let (ma, mb) = (a.manifest.clone(), b.manifest.clone());
    let (ra, rb) = (a.raw.clone(), b.raw.clone());
    let got = tokio::task::spawn_blocking(move || {
        let dl = || Instant::now() + Duration::from_secs(10);
        let mut c = Client::connect(&run, me(), dl()).unwrap();
        let obj = |v: Value| -> Map<String, Value> { v.as_object().cloned().unwrap() };
        let mut out = Vec::new();
        for (m, raw) in [(&ma, &ra), (&mb, &rb)] {
            let f = File::open(raw).unwrap();
            let ans = c
                .call_with_fds(
                    "box.image.import",
                    obj(json!({"manifest": serde_json::to_value(m).unwrap()})),
                    &[f.as_fd()],
                    dl(),
                )
                .unwrap();
            out.push(Value::Object(ans));
        }
        let refused = |r: Result<Map<String, Value>, ClientError>| match r {
            Err(ClientError::Refused { code, message }) => format!("{code}: {message}"),
            other => panic!("not refused: {other:?}"),
        };
        // `id` is the frame's own: no image is named.
        out.push(json!(refused(c.call(
            "box.image.default",
            obj(json!({"id": ma.id})),
            dl()
        ))));
        out.push(Value::Object(
            c.call("box.image.default", obj(json!({"image": ma.id})), dl())
                .unwrap(),
        ));
        out.push(json!(refused(c.call(
            "box.image.rm",
            obj(json!({"id": mb.id})),
            dl()
        ))));
        out.push(Value::Object(
            c.call("box.image.rm", obj(json!({"image": mb.id})), dl())
                .unwrap(),
        ));
        out
    })
    .await
    .unwrap();
    server.abort();
    assert_eq!(got[0]["image"], a.manifest.id.as_str(), "{}", got[0]);
    assert_eq!(got[1]["image"], b.manifest.id.as_str(), "{}", got[1]);
    let r = got[2].as_str().unwrap();
    assert!(r.starts_with("bad_request") && r.contains("image"), "{r}");
    assert_eq!(got[3].get("image"), None, "{}", got[3]);
    let r = got[4].as_str().unwrap();
    assert!(r.starts_with("bad_request") && r.contains("image"), "{r}");
    assert_eq!(
        std::fs::read_to_string(w.paths.records.join("default")).unwrap(),
        format!("{}\n", a.manifest.id)
    );
    let i = &a.manifest.id;
    assert_eq!(
        w.store_names(),
        vec![
            format!("i/{i}.raw"),
            format!("r/{i}.json"),
            "r/default".into()
        ]
    );
    let actions: Vec<String> = w
        .image_records()
        .iter()
        .map(|r| r["action"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        actions,
        [
            "image_import",
            "image_import",
            "image_default",
            "image_remove"
        ]
    );
    let rm = w.image_records().pop().unwrap();
    assert_eq!(rm["image"], b.manifest.id.as_str());
    assert_eq!(rm["sha256"], b.manifest.sha256.as_str());
}

/// Any box record names the image, whatever its owner and state: a
/// running box, a stopped one with a kept snapshot, a discarded one. Only
/// gc frees it.
#[tokio::test]
async fn rm_refuses_an_image_in_use() {
    let w = world(Mode::Locked);
    let s = w.src("a", "image-a\n");
    w.imported(ROOT, &s, false).await;
    let i = s.manifest.id.clone();
    w.vmm.set_image(Some(&i));
    let b = w.spawn(ALICE).await;
    assert_eq!(b["id"], "b1");
    w.mgr.guest_event(&id("b1"), GuestEvent::Ready).unwrap();
    let rm = json!({"image": i});
    let refused = |a: &Value| {
        assert_eq!(a["ok"], false, "{a}");
        assert_eq!(a["error"], "bad_request", "{a}");
        assert!(a["message"].as_str().unwrap().contains("b1"), "{a}");
    };
    refused(&w.call(ROOT, "box.image.rm", rm.clone()).await);
    // ls names the box for an admin and its owner.
    for uid in [ROOT, ALICE] {
        let a = w.ok(uid, "box.image.ls", json!({})).await;
        assert_eq!(a["images"][0]["in_use"], json!(["b1"]), "{a}");
    }
    w.ok(ALICE, "box.stop", json!({"box": "b1", "keep": true}))
        .await;
    assert!(!w.mgr.get(&id("b1")).unwrap().vm_on);
    refused(&w.call(ROOT, "box.image.rm", rm.clone()).await);
    // Discarding a stopped box removes its record at once: it no longer
    // names the image.
    w.ok(ALICE, "box.discard", json!({"box": "b1"})).await;
    assert!(w.mgr.get(&id("b1")).is_err());
    // A box whose boot failed stays as a Discarded record until gc, and
    // it still names the image.
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let b = w.spawn(ALICE).await;
    assert_eq!(b["id"], "b2");
    let r = w.mgr.get(&id("b2")).unwrap();
    assert_eq!(r.state, saiife_boxes::BoxState::Discarded);
    assert_eq!(r.image.as_deref(), Some(i.as_str()));
    let a = w.call(ROOT, "box.image.rm", rm.clone()).await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a["message"].as_str().unwrap().contains("b2"), "{a}");
    w.ok(ROOT, "box.gc", json!({})).await;
    assert!(w.mgr.get(&id("b2")).is_err());
    w.ok(ROOT, "box.image.rm", rm).await;
    assert!(w.store_names().is_empty(), "{:?}", w.store_names());
    let _ = &w.guest;
}

#[tokio::test]
async fn rm_refuses_the_default() {
    let w = world(Mode::Personal);
    let s = w.src("a", "image-a\n");
    w.imported(me(), &s, true).await;
    let a = w
        .call(me(), "box.image.rm", json!({"image": s.manifest.id}))
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(a["message"].as_str().unwrap().contains("default"), "{a}");
    assert_eq!(w.store_names().len(), 3, "{:?}", w.store_names());
    let a = w
        .call(me(), "box.image.rm", json!({"image": image_id(&hex('9'))}))
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
}

/// The base image's id is in the audit log for every box start: the spawn
/// record of a box admitted at its own spawn, the tick record of a queue
/// head admitted later; `BoxRecord.image` is set at admission.
#[tokio::test]
async fn admission_record_names_the_image() {
    let w = world(Mode::Locked);
    let img = image_id(&hex('a'));
    w.vmm.set_image(Some(&img));
    for want in ["b1", "b2"] {
        let b = w.spawn(ALICE).await;
        assert_eq!(b["id"], want);
        assert_eq!(b["state"], "starting");
    }
    let b3 = w.spawn(ALICE).await;
    assert_eq!(b3["state"], "queued");
    assert_eq!(w.mgr.get(&id("b3")).unwrap().image, None);
    let spawns: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["action"] == "spawn")
        .collect();
    assert_eq!(spawns.len(), 3);
    assert_eq!(spawns[0]["image"], img.as_str());
    assert_eq!(spawns[1]["image"], img.as_str());
    assert_eq!(spawns[2].get("image"), None, "{}", spawns[2]);
    assert_eq!(
        w.mgr.get(&id("b1")).unwrap().image.as_deref(),
        Some(img.as_str())
    );
    // b1 stops and goes; the tick admits b3.
    w.mgr.guest_event(&id("b1"), GuestEvent::Ready).unwrap();
    w.ok(ALICE, "box.stop", json!({"box": "b1"})).await;
    w.ok(ALICE, "box.discard", json!({"box": "b1"})).await;
    let before = w.records().len();
    box_ops::tick_once(&w.ctx).await;
    let new: Vec<Value> = w.records()[before..].to_vec();
    let admit: Vec<&Value> = new
        .iter()
        .filter(|r| r["box"] == "b3" && r["to"] == "starting")
        .collect();
    assert_eq!(admit.len(), 1, "{new:?}");
    assert_eq!(admit[0]["via"], "tick");
    assert_eq!(admit[0]["image"], img.as_str());
    assert_eq!(
        w.mgr.get(&id("b3")).unwrap().image.as_deref(),
        Some(img.as_str())
    );
}

/// The manager learns the image from `Vmm::image_id`, never from the
/// handle's data: data that is not JSON still admits.
#[tokio::test]
async fn manager_never_parses_handle_data() {
    let w = world(Mode::Locked);
    let img = image_id(&hex('b'));
    w.vmm.set_handle_data("\u{1}not json at all {");
    w.vmm.set_image(Some(&img));
    let b = w.spawn(ALICE).await;
    assert_eq!(b["state"], "starting");
    let r = w.mgr.get(&id("b1")).unwrap();
    assert_eq!(r.vm.unwrap().data, "\u{1}not json at all {");
    assert_eq!(r.image.as_deref(), Some(img.as_str()));
    // A driver that cannot say: no image, still admitted.
    w.vmm.set_image(None);
    let b = w.spawn(ALICE).await;
    assert_eq!(b["state"], "starting");
    assert_eq!(w.mgr.get(&id("b2")).unwrap().image, None);
}

/// Plan 34's `box.json`, written before the image was resolved, has no
/// `image` key: it loads, as `None`.
#[tokio::test]
async fn old_box_json_without_image_loads() {
    let w = world(Mode::Locked);
    w.spawn(ALICE).await;
    let root = w.mgr.root().to_path_buf();
    let p = root.join("b1").join("box.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("image");
    std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
    let r = Store::open(root).unwrap().load(&id("b1")).unwrap().unwrap();
    assert_eq!(r.image, None);
    assert_eq!(r.id, id("b1"));
}

/// The daemon's image store paths: personal under the state dir (the
/// images dir is the personal layout's), locked split between the
/// daemon's state and the box layout's images dir.
#[test]
fn image_store_paths_follow_the_layout() {
    use saiife_boxhost::layout::Layout;
    use saiife_daemon::box_images::paths_for;
    let state = Path::new("/s/state");
    let p = paths_for(state, &Mode::Personal);
    assert_eq!(p.records, PathBuf::from("/s/state/image-records"));
    assert_eq!(
        p.images,
        Layout::personal(state, Path::new("/s/data")).images
    );
    let l = paths_for(Path::new("/var/lib/saiife"), &Mode::Locked);
    assert_eq!(l.records, PathBuf::from("/var/lib/saiife/images"));
    assert_eq!(l.images, Layout::locked().images);
}

/// rm and default of the same image, racing: the store lock orders them,
/// so the default never names a missing image. The test holds the lock
/// while both start, shows neither finishes under it, then lets them go.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn rm_racing_default_never_leaves_a_missing_default() {
    let w = Arc::new(world(Mode::Personal));
    let a = w.src("a", "image-a\n");
    let b = w.src("b", "image-b\n");
    w.imported(me(), &a, false).await;
    w.imported(me(), &b, true).await;
    let ia = a.manifest.id.clone();
    let held = saiife_daemon::box_images::store_lock();
    let (w1, w2) = (Arc::clone(&w), Arc::clone(&w));
    let (i1, i2) = (ia.clone(), ia.clone());
    let rm = tokio::spawn(async move { w1.call(me(), "box.image.rm", json!({"image": i1})).await });
    let def = tokio::spawn(async move {
        w2.call(me(), "box.image.default", json!({"image": i2}))
            .await
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !rm.is_finished() && !def.is_finished(),
        "both wait for the lock"
    );
    drop(held);
    let (rm, def) = (rm.await.unwrap(), def.await.unwrap());
    // Exactly one wins, and the store stays consistent either way.
    assert_ne!(rm["ok"], def["ok"], "rm {rm} default {def}");
    let default = std::fs::read_to_string(w.paths.records.join("default")).unwrap();
    let default = default.trim();
    assert!(
        w.paths.records.join(format!("{default}.json")).is_file()
            && w.paths.images.join(format!("{default}.raw")).is_file(),
        "the default {default} is missing; rm {rm} default {def}"
    );
    if rm["ok"] == true {
        assert_eq!(default, b.manifest.id, "{def}");
    } else {
        assert_eq!(default, ia, "{rm}");
        assert!(rm["message"].as_str().unwrap().contains("default"), "{rm}");
    }
}

/// A subdir of `<images>/.incoming` left by a daemon that died
/// mid-import is swept by the next import; a link there is not followed.
#[tokio::test]
async fn import_sweeps_stale_incoming() {
    let w = world(Mode::Personal);
    let inc = w.paths.images.join(".incoming");
    let stale = inc.join("00112233aabbccdd");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("base.raw"), "half an image").unwrap();
    let outside = w.tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("base.raw"), "keep me").unwrap();
    std::os::unix::fs::symlink(&outside, inc.join("0011223344556677")).unwrap();
    let s = w.src("a", "image-a\n");
    w.imported(me(), &s, false).await;
    assert!(!stale.exists(), "the stale import dir is swept");
    assert_eq!(
        std::fs::read_to_string(outside.join("base.raw")).unwrap(),
        "keep me"
    );
    let left: Vec<String> = std::fs::read_dir(&inc)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["0011223344556677"], "only the link is left");
}

/// Lockdown `all` refuses import, default and rm with a deny record; ls
/// stays open.
#[tokio::test]
async fn lockdown_refuses_image_changes() {
    use saiife_broker::pipeline::{LockScope, Lockdown};
    let w = world(Mode::Locked);
    let s = w.src("a", "image-a\n");
    w.imported(ROOT, &s, false).await;
    w.ctx
        .lockdown
        .set(Some(Lockdown {
            scope: LockScope::All,
            reason: "incident".into(),
            by_uid: 0,
            since: "t".into(),
        }))
        .unwrap();
    let before = w.image_records().len();
    let b = w.src("b", "image-b\n");
    let a = w.import(ROOT, &b, true).await;
    assert_eq!(a["error"], "lockdown", "{a}");
    assert_eq!(a["rule"], "lockdown", "{a}");
    let img = json!({"image": s.manifest.id});
    for op in ["box.image.default", "box.image.rm"] {
        let a = w.call(ROOT, op, img.clone()).await;
        assert_eq!(a["error"], "lockdown", "{op}: {a}");
    }
    let a = w.ok(ROOT, "box.image.ls", json!({})).await;
    assert_eq!(a["images"].as_array().unwrap().len(), 1, "{a}");
    let i = &s.manifest.id;
    assert_eq!(
        w.store_names(),
        vec![format!("i/{i}.raw"), format!("r/{i}.json")]
    );
    let recs = w.image_records();
    let new = &recs[before..];
    let actions: Vec<&str> = new.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["image_import", "image_default", "image_remove"]);
    for r in new {
        assert_eq!(r["decision"], "deny", "{r}");
        assert_eq!(r["rule"], "lockdown", "{r}");
    }
    assert_eq!(new[0]["image"], b.manifest.id.as_str());
    assert_eq!(new[1]["image"], i.as_str());
}

/// The import is in the store and recorded even when `--default` then
/// fails: the answer is ok and says why the default did not change.
#[tokio::test]
async fn import_default_error_is_ok_with_the_image() {
    let w = world(Mode::Personal);
    // `default` is a dir here, so it cannot be replaced.
    std::fs::create_dir_all(w.paths.records.join("default")).unwrap();
    std::fs::write(w.paths.records.join("default/x"), "x").unwrap();
    let s = w.src("a", "image-a\n");
    let a = w.import(me(), &s, true).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["image"], s.manifest.id.as_str(), "{a}");
    assert!(
        a["default_error"].as_str().is_some_and(|e| !e.is_empty()),
        "{a}"
    );
    let actions: Vec<String> = w
        .image_records()
        .iter()
        .map(|r| r["action"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(actions, ["image_import"]);
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert_eq!(a["images"][0]["id"], s.manifest.id.as_str());
    assert_eq!(a["images"][0]["default"], false);
}

/// Plan 35's preflight wants a default image, and plan 36's import makes
/// one: with no manager (the preflight failed) the image ops still serve
/// the store. ls names no box, rm is refused (box records it cannot see
/// may name the image), import says a restart uses it; other box ops stay
/// unavailable with the preflight's why.
#[tokio::test]
async fn image_ops_work_without_a_manager() {
    let w = world_with(Mode::Personal, false);
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert_eq!(a["images"], json!([]));
    let s = w.src("a", "image-a\n");
    let a = w.import(me(), &s, true).await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a.get("default_error").is_none(), "{a}");
    assert!(a["note"].as_str().unwrap().contains("restart"), "{a}");
    assert_eq!(
        std::fs::read_to_string(w.paths.records.join("default")).unwrap(),
        format!("{}\n", s.manifest.id)
    );
    let a = w.ok(me(), "box.image.ls", json!({})).await;
    assert_eq!(a["images"][0]["default"], true, "{a}");
    assert_eq!(a["images"][0]["in_use"], json!([]), "{a}");
    let a = w
        .call(me(), "box.image.rm", json!({"image": s.manifest.id}))
        .await;
    assert_eq!(a["error"], "unavailable", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains(UNAVAILABLE_WHY),
        "{a}"
    );
    let a = w.call(me(), "box.list", json!({})).await;
    assert_eq!(a["error"], "unavailable", "{a}");
    assert_eq!(a["message"], UNAVAILABLE_WHY, "{a}");
    // with a manager an import carries no note
    let w = world(Mode::Personal);
    let a = w.import(me(), &w.src("b", "image-b\n"), false).await;
    assert!(a.get("note").is_none(), "{a}");
}
