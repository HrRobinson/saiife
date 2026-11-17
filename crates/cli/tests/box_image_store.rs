//! `saiife box image import|ls|default|rm` (plan 36, Task 5) against a real
//! personal broker whose boxes run on the fake VM (`fake-vmm` build,
//! `SAIIFE_BOX_FAKE_VMM=1`). The image store is the broker's own, under
//! its state dir; no VM is ever started.
#![cfg(all(target_os = "linux", feature = "fake-vmm"))]

mod common;

use common::personal::TestBroker;
use saiife_boxhost::image::ubuntu::UBUNTU_CLOUD_FPR;
use saiife_boxhost::image::{
    image_id, Manifest, ManifestBoot, ManifestPin, ManifestUbuntu, ManifestVmm,
};
use saiife_boxhost::pins::sha256_file;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

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
        capabilities: vec![saiife_boxhost::image::CLAUDE_MANAGED_SETTINGS.into()],
        packages: Vec::new(),
        images: Vec::new(),
        boot: ManifestBoot::Firmware,
        signature: None,
    }
}

fn broker() -> TestBroker {
    let mut b = TestBroker::prepare();
    b.env.push(("SAIIFE_BOX_FAKE_VMM".into(), Some("1".into())));
    b.spawn_and_wait();
    b
}

/// A built image as `saiife box image build` leaves it: `<dir>/<id>.raw`
/// and `<dir>/<id>.json`. Returns the raw path and the id.
fn built(b: &TestBroker, dir: &str, content: &str) -> (PathBuf, String) {
    let d = b.path().join(dir);
    fs::create_dir_all(&d).unwrap();
    let tmp = d.join("tmp.raw");
    fs::write(&tmp, content).unwrap();
    let m = manifest_for(&sha256_file(&tmp).unwrap());
    let raw = d.join(format!("{}.raw", m.id));
    fs::rename(&tmp, &raw).unwrap();
    fs::write(d.join(format!("{}.json", m.id)), m.to_json()).unwrap();
    (raw, m.id)
}

fn image(b: &TestBroker, args: &[&str]) -> Output {
    let mut all = vec!["box", "image"];
    all.extend_from_slice(args);
    b.run_cli(&all)
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn ls_json(b: &TestBroker) -> Value {
    let o = image(b, &["ls", "--json"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    serde_json::from_str(&out(&o)).unwrap()
}

/// The broker's image store: `(records, images)` names.
fn store(b: &TestBroker) -> Vec<String> {
    let ls = |d: &Path, pre: &str| -> Vec<String> {
        match fs::read_dir(d) {
            Ok(rd) => rd
                .map(|e| format!("{pre}{}", e.unwrap().file_name().to_string_lossy()))
                .filter(|n| !n.ends_with(".incoming"))
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    let mut v = ls(&b.state_dir().join("image-records"), "r/");
    v.extend(ls(&b.state_dir().join("images"), "i/"));
    v.sort();
    v
}

/// The CLI opens the image, its manifest and its kernel `O_NOFOLLOW`: a
/// symlink to a good image is refused before anything reaches the daemon.
#[test]
fn import_refuses_a_symlink_fd_target() {
    let b = broker();
    let (raw, id) = built(&b, "out", "image-a\n");
    let links = b.path().join("links");
    fs::create_dir(&links).unwrap();
    // The image itself through a link.
    let link = links.join(format!("{id}.raw"));
    std::os::unix::fs::symlink(&raw, &link).unwrap();
    fs::copy(raw.with_extension("json"), link.with_extension("json")).unwrap();
    let o = image(&b, &["import", link.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    // The manifest through a link.
    let other = b.path().join("other");
    fs::create_dir(&other).unwrap();
    let raw2 = other.join(format!("{id}.raw"));
    fs::copy(&raw, &raw2).unwrap();
    std::os::unix::fs::symlink(raw.with_extension("json"), raw2.with_extension("json")).unwrap();
    let o = image(&b, &["import", raw2.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    // Not a .raw.
    let o = image(&b, &["import", b.path().join("out").to_str().unwrap()]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(store(&b).is_empty(), "{:?}", store(&b));
    // The file itself goes in.
    let o = image(&b, &["import", raw.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(out(&o), format!("imported {id}\n"));
    assert_eq!(
        store(&b),
        vec![format!("i/{id}.raw"), format!("r/{id}.json")]
    );
}

/// `default` and `rm` send `{image}` (an `id` key would be the frame's own);
/// the answer of `import` names the image.
#[test]
fn default_and_rm_take_image_not_id() {
    let b = broker();
    let (a_raw, a) = built(&b, "a", "image-a\n");
    let (b_raw, b_id) = built(&b, "b", "image-b\n");
    let o = image(&b, &["import", "--default", a_raw.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(out(&o), format!("imported {a}\ndefault image {a}\n"));
    let o = image(&b, &["import", b_raw.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v = ls_json(&b);
    let images = v["images"].as_array().unwrap();
    assert_eq!(images.len(), 2, "{v}");
    for i in images {
        assert_eq!(i["default"], i["id"] == a.as_str(), "{i}");
        assert_eq!(i["in_use"], serde_json::json!([]), "{i}");
    }
    // The table.
    let o = image(&b, &["ls"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    let head = t.lines().next().unwrap();
    for h in ["ID", "DEFAULT", "UBUNTU", "CLAUDE", "SIZE", "IN USE"] {
        assert!(head.contains(h), "{t}");
    }
    assert!(t.contains("release-20261017") && t.contains("9.9.9"), "{t}");
    // default moves; the default cannot be removed; another image can.
    let o = image(&b, &["default", &b_id]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(out(&o), format!("default image {b_id}\n"));
    let o = image(&b, &["rm", &b_id]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(err(&o).contains("default"), "{}", err(&o));
    let o = image(&b, &["rm", &a]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(out(&o), format!("removed {a}\n"));
    let o = image(&b, &["rm", "base-nope"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(err(&o).contains("image"), "{}", err(&o));
    assert_eq!(
        store(&b),
        vec![
            format!("i/{b_id}.raw"),
            format!("r/{b_id}.json"),
            "r/default".to_string(),
        ]
    );
}

/// `import --default` whose default step fails: the image is in the store,
/// the CLI prints it and why it is not the default, and exits 2.
#[test]
fn import_default_error_exits_2_after_the_import() {
    let b = broker();
    let records = b.state_dir().join("image-records");
    fs::create_dir_all(records.join("default")).unwrap();
    fs::write(records.join("default/x"), "x").unwrap();
    let (raw, id) = built(&b, "out", "image-a\n");
    let o = image(&b, &["import", "--default", raw.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert_eq!(out(&o), format!("imported {id}\n"));
    assert!(
        err(&o).contains(&id) && err(&o).contains("not the default"),
        "{}",
        err(&o)
    );
    let v = ls_json(&b);
    assert_eq!(v["images"][0]["id"], id.as_str(), "{v}");
    assert_eq!(v["images"][0]["default"], false, "{v}");
}

/// The hint a box without a default image gets (R43) names a command this
/// build has: `image import` with `--default`.
#[test]
fn default_image_hint_command_exists() {
    let hint = saiife_boxhost::image::DEFAULT_IMAGE_HINT;
    assert!(hint.contains("saiife box image import --default"), "{hint}");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["box", "image", "import", "--help"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("--default"), "{}", out(&o));
}
