use std::fs;
#[cfg(unix)]
use std::path::Path;

use saiife_boxes::store::{BoxRecord, Store, VmHandle};
use saiife_boxes::template::Size;
use saiife_boxes::{BoxId, BoxState};

fn id(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

fn rec(i: &BoxId) -> BoxRecord {
    BoxRecord {
        version: 1,
        id: i.clone(),
        state: BoxState::Running,
        owner_uid: 1000,
        session: format!("box-{}", i.as_str()),
        template: "claude-code".into(),
        size: Size::default(),
        repo: "shop".into(),
        repo_dir: Some("/home/u/shop".into()),
        task: "do the thing".into(),
        created_at: 10,
        started_at: Some(11),
        updated_at: 12,
        queue_seq: Some(3),
        vm: Some(VmHandle {
            id: i.clone(),
            driver: "fake".into(),
            data: "{}".into(),
        }),
        vm_on: true,
        keep: false,
        lands: 2,
        last_activity: 13,
        turn_finished_at: Some(14),
        pending_prompt: Some("go".into()),
        error: None,
        image: Some("img-1".into()),
    }
}

fn open(t: &tempfile::TempDir) -> Store {
    Store::open(t.path().join("boxes")).unwrap()
}

fn marker(i: &str) -> String {
    format!("saiife.managed box {i}\n")
}

#[test]
fn claim_ids_are_sequential_and_never_reused() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    assert_eq!(s.claim_id().unwrap(), id("b1"));
    let b2 = s.claim_id().unwrap();
    assert_eq!(b2, id("b2"));
    assert_eq!(
        fs::read_to_string(s.box_dir(&b2).join(".saiife-box")).unwrap(),
        marker("b2")
    );
    s.remove(&b2).unwrap();
    assert_eq!(s.claim_id().unwrap(), id("b3"));

    let t2 = tempfile::tempdir().unwrap();
    let s2 = open(&t2);
    s2.claim_id().unwrap();
    s2.claim_id().unwrap();
    fs::create_dir(s2.root().join("b3")).unwrap();
    assert_eq!(s2.claim_id().unwrap(), id("b4"));
}

#[test]
fn save_load_roundtrip() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let i = s.claim_id().unwrap();
    let r = rec(&i);
    s.save(&r).unwrap();
    assert_eq!(s.load(&i).unwrap(), Some(r.clone()));
    assert_eq!(s.load(&id("b9")).unwrap(), None);
    let (all, warns) = s.list().unwrap();
    assert_eq!(all, vec![r]);
    assert!(warns.is_empty());
}

#[test]
fn record_without_image_loads() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let i = s.claim_id().unwrap();
    let mut r = rec(&i);
    r.image = None;
    s.save(&r).unwrap();
    let file = s.box_dir(&i).join("box.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("image").unwrap();
    fs::write(&file, v.to_string()).unwrap();
    assert_eq!(s.load(&i).unwrap(), Some(r));
}

#[test]
fn save_is_atomic() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let i = s.claim_id().unwrap();
    let mut r = rec(&i);
    s.save(&r).unwrap();
    r.state = BoxState::Done;
    s.save(&r).unwrap();
    let names: Vec<String> = fs::read_dir(s.box_dir(&i))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.contains(".tmp.")), "{names:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&s.box_dir(&i).join("box.json")), 0o600);
        assert_eq!(mode(s.root()), 0o700);
        assert_eq!(mode(&s.root().join("next-id")), 0o600);
    }
}

#[test]
fn save_refuses_without_marker() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    fs::create_dir(s.root().join("b1")).unwrap();
    assert!(s.save(&rec(&id("b1"))).is_err());
}

fn mk(s: &Store, name: &str, marker_text: Option<&str>, json: Option<String>) {
    let d = s.root().join(name);
    fs::create_dir(&d).unwrap();
    if let Some(m) = marker_text {
        fs::write(d.join(".saiife-box"), m).unwrap();
    }
    if let Some(j) = json {
        fs::write(d.join("box.json"), j).unwrap();
    }
}

#[test]
fn bad_records_are_skipped_and_named() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let json = |i: &str| serde_json::to_value(rec(&id(i))).unwrap();
    let mut unk = json("b1");
    unk["surprise"] = 1.into();
    mk(&s, "b1", Some(&marker("b1")), Some(unk.to_string()));
    mk(&s, "b2", Some(&marker("b2")), Some(json("b7").to_string()));
    mk(&s, "b3", None, Some(json("b3").to_string()));
    let mut v2 = json("b4");
    v2["version"] = 2.into();
    mk(&s, "b4", Some(&marker("b4")), Some(v2.to_string()));
    mk(
        &s,
        "README",
        Some(&marker("README")),
        Some(json("b5").to_string()),
    );
    let (all, warns) = s.list().unwrap();
    assert!(all.is_empty());
    assert_eq!(warns.len(), 5, "{warns:?}");
    for n in ["b1", "b2", "b3", "b4", "README"] {
        assert!(warns.iter().any(|w| w.contains(n)), "{n}: {warns:?}");
    }
}

#[cfg(unix)]
#[test]
fn remove_refuses_a_symlinked_dir() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join(".saiife-box"), marker("b9")).unwrap();
    fs::write(other.path().join("canary"), "x").unwrap();
    std::os::unix::fs::symlink(other.path(), s.root().join("b9")).unwrap();
    assert!(s.remove(&id("b9")).is_err());
    assert!(other.path().join("canary").exists());
    let (all, warns) = s.list().unwrap();
    assert!(all.is_empty());
    assert_eq!(warns.len(), 1);
    assert!(s.orphans().unwrap().is_empty());
}

#[test]
fn remove_refuses_wrong_marker() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    mk(&s, "b1", Some(&marker("b2")), None);
    fs::write(s.root().join("b1").join("canary"), "x").unwrap();
    assert!(s.remove(&id("b1")).is_err());
    assert!(s.root().join("b1").join("canary").exists());
    mk(&s, "b2", None, None);
    assert!(s.remove(&id("b2")).is_err());
}

#[test]
fn orphans_skip_unmarked_dirs() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let good = s.claim_id().unwrap();
    s.save(&rec(&good)).unwrap();
    let orphan = s.claim_id().unwrap();
    mk(&s, "b9", None, None);
    mk(&s, "b8", Some(&marker("b7")), None);
    assert_eq!(s.orphans().unwrap(), vec![orphan]);
}

#[test]
fn list_ignores_tmp_files() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let i = s.claim_id().unwrap();
    s.save(&rec(&i)).unwrap();
    fs::write(s.box_dir(&i).join("box.json.tmp.123"), "{").unwrap();
    fs::write(s.root().join("next-id.tmp.123"), "x").unwrap();
    let (all, warns) = s.list().unwrap();
    assert_eq!(all.len(), 1);
    assert!(warns.is_empty(), "{warns:?}");
}

#[test]
fn unreadable_records_are_not_orphans() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let json = |i: &str| serde_json::to_value(rec(&id(i))).unwrap();
    let mut v2 = json("b1");
    v2["version"] = 2.into();
    mk(&s, "b1", Some(&marker("b1")), Some(v2.to_string()));
    let mut unk = json("b2");
    unk["surprise"] = 1.into();
    mk(&s, "b2", Some(&marker("b2")), Some(unk.to_string()));
    mk(&s, "b3", Some(&marker("b3")), Some("{".into()));
    mk(&s, "b4", Some(&marker("b4")), None);
    assert_eq!(s.orphans().unwrap(), vec![id("b4")]);
}

#[test]
fn tmp_names_are_unique_within_a_process() {
    let t = tempfile::tempdir().unwrap();
    let s = std::sync::Arc::new(open(&t));
    let i = s.claim_id().unwrap();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (s, i) = (s.clone(), i.clone());
            std::thread::spawn(move || {
                for _ in 0..50 {
                    s.save(&rec(&i)).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.load(&i).unwrap(), Some(rec(&i)));
}

#[test]
fn hostile_counter_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    fs::write(s.root().join("next-id"), u64::MAX.to_string()).unwrap();
    fs::create_dir(s.root().join(format!("b{}", u64::MAX))).ok();
    assert!(s.claim_id().is_err());
}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

/// Personal mode: the root and every box dir are the user's alone.
#[cfg(unix)]
#[test]
fn personal_store_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("boxes");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let s = Store::open(root.clone()).unwrap();
    assert_eq!(mode_of(&root), 0o700);
    let b = s.claim_id().unwrap();
    assert_eq!(mode_of(&s.box_dir(&b)), 0o700);
}

/// S6/R37: a box's record files are read without following links, and only
/// when they are plain files of this uid with one link: anything else makes
/// the box corrupt (a warning), never trusted, never removed.
#[cfg(unix)]
#[test]
fn symlinked_or_hard_linked_records_are_corrupt_and_kept() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let outside = t.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = outside.join("box.json");
    let b1 = s.claim_id().unwrap();
    s.save(&rec(&b1)).unwrap();
    fs::write(&target, serde_json::to_string(&rec(&b1)).unwrap()).unwrap();
    let file = s.box_dir(&b1).join("box.json");
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(&target, &file).unwrap();
    assert!(s.load(&b1).is_err());
    let b2 = s.claim_id().unwrap();
    s.save(&rec(&b2)).unwrap();
    let file2 = s.box_dir(&b2).join("box.json");
    fs::hard_link(&file2, outside.join("other")).unwrap();
    assert!(s.load(&b2).is_err());
    let (all, warns) = s.list().unwrap();
    assert!(all.is_empty(), "{all:?}");
    assert_eq!(warns.len(), 2, "{warns:?}");
    assert!(s.orphans().unwrap().is_empty());
    // a symlinked marker: not labelled, so never removed
    let b3 = s.claim_id().unwrap();
    let m = s.box_dir(&b3).join(".saiife-box");
    fs::write(outside.join("marker"), marker(b3.as_str())).unwrap();
    fs::remove_file(&m).unwrap();
    std::os::unix::fs::symlink(outside.join("marker"), &m).unwrap();
    assert!(s.remove(&b3).is_err());
    assert!(s.box_dir(&b3).exists());
    assert!(target.exists() && outside.join("other").exists());
}

/// A symlinked counter is refused, its target untouched.
#[cfg(unix)]
#[test]
fn symlinked_counter_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let target = t.path().join("elsewhere");
    fs::write(&target, "5").unwrap();
    std::os::unix::fs::symlink(&target, s.root().join("next-id")).unwrap();
    assert!(s.claim_id().is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "5");
}

/// The store root must be a real directory of this uid; a group-writable
/// one of ours is made 0700.
#[cfg(unix)]
#[test]
fn store_root_is_checked() {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(Store::open(link).is_err(), "a symlinked root");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
    Store::open(real.clone()).unwrap();
    assert_eq!(mode_of(&real), 0o700);
    // a file is not a root
    let f = t.path().join("file");
    fs::write(&f, "").unwrap();
    assert!(Store::open(f).is_err());
}

/// R37: a VMM-group write into the runtime dirs (a hostile `box.json`,
/// marker or counter, a planted box dir) is not in the store: it changes
/// nothing listed, nothing claimed and nothing removed.
#[cfg(unix)]
#[test]
fn runtime_files_are_not_records() {
    let t = tempfile::tempdir().unwrap();
    let s = open(&t);
    let b1 = s.claim_id().unwrap();
    s.save(&rec(&b1)).unwrap();
    let run = t.path().join("box-run");
    fs::create_dir_all(run.join("b1")).unwrap();
    fs::create_dir_all(run.join("b9")).unwrap();
    let mut evil = rec(&b1);
    evil.owner_uid = 0;
    evil.state = BoxState::Done;
    fs::write(
        run.join("b1/box.json"),
        serde_json::to_string(&evil).unwrap(),
    )
    .unwrap();
    fs::write(run.join("b1/.saiife-box"), marker("b1")).unwrap();
    fs::write(run.join("b9/.saiife-box"), marker("b9")).unwrap();
    fs::write(run.join("next-id"), "1").unwrap();
    let (all, warns) = s.list().unwrap();
    assert_eq!(all, vec![rec(&b1)], "{warns:?}");
    assert!(s.orphans().unwrap().is_empty());
    assert_eq!(s.claim_id().unwrap(), id("b2"));
    assert!(run.join("b9").exists() && run.join("b1/box.json").exists());
}
