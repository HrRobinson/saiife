//! Data Shield test pieces shared by `blind_cli` (plan 48 T4, T5) and
//! `blind_init` (T6): the synthetic `crm` fixture (made-up Danish and
//! English names only), the pinned name-detector files, the fake detector
//! (`SAIIFE_TEST_NER_HELPER` = `saiife-fake-ner`), the scripted planner
//! (`SAIIFE_TEST_BLIND_PLANNER`) and this `saiife` as the calculator
//! (`SAIIFE_TEST_BLIND_CALC`). No network.
#![allow(dead_code)]

use super::personal::TestBroker;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const FIRST: &[&str] = &[
    "Mette", "Jens", "Lars", "Freja", "Mads", "Ida", "Niels", "Karen", "Emil", "Oliver", "Emma",
    "James", "Sophie", "Thomas", "Lucy",
];
const LAST: &[&str] = &[
    "Jensen", "Nielsen", "Hansen", "Pedersen", "Andersen", "Larsen", "Møller", "Smith",
];
const CITY: &[&str] = &["Aalborg", "Esbjerg", "London", "Leeds", "Vejle"];

/// The synthetic `crm`: customers 1 Søren Østergård (København), 2 Anna
/// Berg (Aarhus), 3 Anna Berg (Odense), then made-up names that are each
/// unique; every customer has invoices, both statuses held by many.
/// With `email`, customers also have a made-up `email` (`p<id>@mail.example`).
pub fn fixture_sqlite(path: &Path, email: bool) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, city TEXT);
         CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, status TEXT);",
    )
    .unwrap();
    if email {
        c.execute_batch("ALTER TABLE customers ADD COLUMN email TEXT;")
            .unwrap();
    }
    let mut people: Vec<(String, String, String)> = vec![
        ("Søren".into(), "Østergård".into(), "København".into()),
        ("Anna".into(), "Berg".into(), "Aarhus".into()),
        ("Anna".into(), "Berg".into(), "Odense".into()),
    ];
    for (i, l) in LAST.iter().enumerate() {
        for (j, f) in FIRST.iter().enumerate() {
            people.push((
                f.to_string(),
                l.to_string(),
                CITY[(i + j) % CITY.len()].to_string(),
            ));
        }
    }
    let mut inv = 1000;
    for (n, (f, l, city)) in people.iter().enumerate() {
        let id = n as i64 + 1;
        if email {
            c.execute(
                "INSERT INTO customers VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![id, f, l, city, format!("p{id}@mail.example")],
            )
            .unwrap();
        } else {
            c.execute(
                "INSERT INTO customers VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id, f, l, city],
            )
            .unwrap();
        }
        let amounts: Vec<(f64, &str)> = match id {
            1 => vec![(100.0, "paid"), (200.0, "open"), (300.0, "open")],
            2 => vec![(1000.0, "open"), (500.5, "paid")],
            3 => vec![(42.0, "open")],
            _ => vec![(10.0 + id as f64, "paid"), (20.0 + id as f64, "open")],
        };
        for (a, st) in amounts {
            inv += 1;
            c.execute(
                "INSERT INTO invoices VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![inv, id, a, st],
            )
            .unwrap();
        }
    }
}

/// The URLs the tests pin the name-detector files at (never fetched: the
/// files are stored where a fetch would put them).
pub const NER_URLS: [&str; 3] = [
    "https://ner.example.test/m",
    "https://ner.example.test/v",
    "https://ner.example.test/l",
];

/// `[blind.ner]` pinning the three files the test wrote, after
/// `version = 2`.
pub fn ner_policy(pins: &[String]) -> String {
    format!(
        "version = 2\n\n[blind.ner]\nmodel_url = \"{}\"\nmodel_sha256 = \"{}\"\n\
         vocab_url = \"{}\"\nvocab_sha256 = \"{}\"\n\
         labels_url = \"{}\"\nlabels_sha256 = \"{}\"\n\n",
        NER_URLS[0], pins[0], NER_URLS[1], pins[1], NER_URLS[2], pins[2]
    )
}

/// `target/debug/saiife-fake-ner`, in the profile dir. Cargo's old layout
/// runs a test from `target/debug/deps/`, the new build dir layout (the
/// default from Rust 1.100) from `target/debug/build/<package>/<hash>/out/`:
/// the profile dir is the parent of the nearest `deps` or `build` above it.
pub fn fake_ner() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile = exe
        .ancestors()
        .find(|d| {
            matches!(
                d.file_name().and_then(|n| n.to_str()),
                Some("deps" | "build")
            )
        })
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("no target profile dir above {}", exe.display()));
    let p = profile.join("saiife-fake-ner");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner` first",
        p.display()
    );
    p
}

pub fn private(p: &Path) {
    fs::create_dir_all(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Before the broker starts: the name-detector files pinned by sha256
/// (R-C8) where a fetch would put them, the fake detector (one made-up
/// stranger, Zed Quorra, is a person), `replies` as the planner's script
/// (`<tmp>/planner.txt`) and the calculator seam. The three pins.
pub fn seams(b: &mut TestBroker, replies: &[String]) -> Vec<String> {
    use sha2::{Digest, Sha256};
    for d in ["s/saiife", "s/saiife/broker", "s/saiife/broker/blind"] {
        private(&b.path().join(d));
    }
    let models = b.state_dir().join("blind/models");
    private(&models);
    let mut pins = Vec::new();
    for x in [&b"model"[..], b"vocab", b"labels"] {
        let h = format!("{:x}", Sha256::digest(x));
        fs::write(models.join(&h), x).unwrap();
        pins.push(h);
    }
    let helper_dir = b.path().join("ner");
    private(&helper_dir);
    let phrases = helper_dir.join("phrases.txt");
    fs::write(&phrases, "PER\tZed Quorra\n").unwrap();
    let helper = helper_dir.join("ner");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nexec '{}' --phrases '{}'\n",
            fake_ner().display(),
            phrases.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let script = b.path().join("planner.txt");
    fs::write(&script, replies.join("\n") + "\n").unwrap();
    let seams: [(&str, OsString); 3] = [
        ("SAIIFE_TEST_NER_HELPER", helper.into()),
        ("SAIIFE_TEST_BLIND_PLANNER", script.into()),
        (
            "SAIIFE_TEST_BLIND_CALC",
            env!("CARGO_BIN_EXE_saiife").into(),
        ),
    ];
    for (k, v) in seams {
        b.env.push((k.to_string(), Some(v)));
    }
    pins
}
