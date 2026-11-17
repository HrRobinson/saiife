//! Plan 43 T7: the atomic dataset build. Every value here is made up.

#[path = "fixtures.rs"]
mod fixtures;

use saiife_shield::dataset::{
    finish, finish_crash_after_first_rename, load_manifest, propose, stage_snapshot, BuildProgress,
    DatasetDir, Format, Manifest, Phase,
};
use saiife_shield::index::{IndexKey, KnownIndex};
use saiife_shield::lexicon::Lexicon;
use saiife_shield::schema::{rows_band, ColumnClass, Schema};
use saiife_shield::ShieldError;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// A fixed test key, never a token-shaped literal.
fn key() -> IndexKey {
    let s = concat!("dataset-test-", "fixed-key-", "not-a-secret");
    let mut k = [0u8; 32];
    for (d, b) in k.iter_mut().zip(s.bytes().cycle()) {
        *d = b;
    }
    IndexKey(Zeroizing::new(k))
}

fn fixture(base: &Path, tag: &str, customers: u64, invoices: u64, seed: u64) -> PathBuf {
    let d = base.join(tag);
    std::fs::create_dir_all(&d).unwrap();
    fixtures::write_fixture_sized(&d, customers, invoices, seed).unwrap();
    d
}

fn ds(base: &Path) -> DatasetDir {
    DatasetDir {
        root: base.join("datasets").join("crm"),
    }
}

fn ok(_: &Manifest) -> Result<(), String> {
    Ok(())
}

/// Stage the CSVs of `csv` and return the accept-all schema.
fn stage(dir: &DatasetDir, csv: &Path) -> Schema {
    let mut src = fixtures::MultiSource::csv_dir(csv).unwrap();
    stage_snapshot(dir, &mut src, &mut |_| {}).unwrap();
    let props = propose(&dir.stage().join("snapshot.sqlite"), 10).unwrap();
    fixtures::accept_all("crm", &props)
}

fn build(dir: &DatasetDir, csv: &Path) -> Manifest {
    let schema = stage(dir, csv);
    finish(dir, &schema, 10, &key(), &mut ok, &mut |_| {}).unwrap()
}

fn first_email(csv: &Path) -> String {
    let mut r = csv::Reader::from_path(csv.join("customers.csv")).unwrap();
    let h = r.headers().unwrap().clone();
    let i = h.iter().position(|c| c == "email").unwrap();
    r.records().next().unwrap().unwrap()[i].to_string()
}

#[test]
fn build_end_to_end() {
    let t = tempfile::tempdir().unwrap();
    let csv = fixture(t.path(), "csv", 2000, 6000, 1);
    let dir = ds(t.path());

    let mut phases: Vec<Phase> = Vec::new();
    let mut src = fixtures::MultiSource::csv_dir(&csv).unwrap();
    let info = stage_snapshot(&dir, &mut src, &mut |p: BuildProgress| {
        if phases.last() != Some(&p.phase) {
            phases.push(p.phase)
        }
    })
    .unwrap();
    assert_eq!(info.tables.len(), 2);
    assert!(!dir.live().exists(), "staging never touches live");

    let props = propose(&dir.stage().join("snapshot.sqlite"), 10).unwrap();
    let p = |t: &str, c: &str| {
        props
            .iter()
            .find(|p| p.table == t && p.column == c)
            .unwrap_or_else(|| panic!("no proposal for {t}.{c}"))
            .clone()
    };
    let status = p("invoices", "status");
    assert_eq!(status.guess.class, ColumnClass::Public);
    assert!(status.uncertain);
    assert_eq!(status.public_refusal, None);
    assert_eq!(
        status.public_preview.unwrap().passing,
        vec!["open", "overdue", "paid"]
    );
    for (tb, c) in [
        ("customers", "email"),
        ("customers", "id"),
        ("invoices", "amount"),
    ] {
        let x = p(tb, c);
        assert!(x.public_refusal.is_some(), "{tb}.{c} must be refused");
        assert_eq!(x.public_preview, None, "{tb}.{c}: no preview once refused");
    }

    let schema = fixtures::accept_all("crm", &props);
    assert_eq!(
        schema.column("invoices", "status").unwrap().class,
        ColumnClass::Public
    );
    let mut seen_validate = false;
    let m = finish(
        &dir,
        &schema,
        10,
        &key(),
        &mut |m: &Manifest| {
            seen_validate = true;
            assert_eq!(m.dataset.as_str(), "crm");
            Ok(())
        },
        &mut |p: BuildProgress| {
            if phases.last() != Some(&p.phase) {
                phases.push(p.phase)
            }
        },
    )
    .unwrap();
    assert!(seen_validate);
    assert_eq!(
        phases,
        vec![
            Phase::Snapshot,
            Phase::Lexicon,
            Phase::Index,
            Phase::Validate,
            Phase::Swap
        ]
    );

    assert_eq!(m.v, 1);
    assert_eq!(m.dataset.as_str(), "crm");
    assert_eq!(m.snapshot_sha256, info.sha256);
    let names: Vec<&str> = m.schema.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["customers", "invoices"]);
    assert_eq!(
        rows_band(m.schema.table("customers").unwrap().rows),
        "about 2 thousand"
    );
    assert_eq!(
        rows_band(m.schema.table("invoices").unwrap().rows),
        "about 6 thousand"
    );
    assert_eq!(m.rows_bands["customers"], "about 2 thousand");
    assert_eq!(m.rows_bands["invoices"], "about 6 thousand");
    let pv = m
        .public
        .iter()
        .find(|p| p.column == "invoices.status")
        .expect("status is public");
    assert_eq!(pv.passing, vec!["open", "overdue", "paid"]);
    assert_eq!(m.formats["customers.email"], Format::Email);
    assert_eq!(m.formats["customers.phone"], Format::Phone);
    assert_eq!(m.formats["customers.ref_code"], Format::Cpr);
    assert_eq!(m.formats["customers.city"], Format::Plain);
    assert_eq!(m.source_names["customers"], "customers");
    assert_eq!(m.source_names["invoices.status"], "status");
    assert!(m.index.entries > 0);
    for f in ["lexicon.sqlite", "index.bin", "index.bloom", "allow.json"] {
        assert!(m.files[f].starts_with("sha256:"), "{f}");
    }
    assert_eq!(m.schema.entities[0].word, "record");
    assert_eq!(m.schema.entities[0].word_da, "post");

    // The live set is complete and usable; the stage is gone.
    assert!(!dir.stage().exists());
    assert_eq!(dir.snapshot(), dir.live().join("snapshot.sqlite"));
    assert_eq!(dir.manifest(), dir.live().join("manifest.json"));
    assert_eq!(load_manifest(&dir).unwrap(), m);
    Lexicon::open(&dir.lexicon()).unwrap();
    let idx = KnownIndex::open(&dir.live(), key()).unwrap();
    assert!(idx.contains_value(&first_email(&csv)).unwrap());
    assert!(!idx.contains_value("paid").unwrap(), "a public value");

    // A flipped bit in the Bloom filter is caught, not a silent miss.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let b = dir.live().join("index.bloom");
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut bytes = std::fs::read(&b).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&b, &bytes).unwrap();
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(load_manifest(&dir), Err(ShieldError::Corrupt(_))));
    }
}

#[test]
fn interrupted_build_leaves_live_intact() {
    let t = tempfile::tempdir().unwrap();
    let dir = ds(t.path());
    let m1 = build(&dir, &fixture(t.path(), "a", 300, 600, 1));

    // A failed validation: live keeps the first build.
    let csv2 = fixture(t.path(), "b", 400, 900, 2);
    let schema = stage(&dir, &csv2);
    let r = finish(
        &dir,
        &schema,
        10,
        &key(),
        &mut |_: &Manifest| Err("the approved methods did not re-validate".into()),
        &mut |_| {},
    );
    assert!(r.is_err());
    let now = load_manifest(&dir).unwrap();
    assert_eq!(now.snapshot_sha256, m1.snapshot_sha256);

    // A crash between the two renames: live is gone, old and stage remain.
    let schema = stage(&dir, &csv2);
    finish_crash_after_first_rename(&dir, &schema, 10, &key(), &mut ok, &mut |_| {}).unwrap();
    assert!(!dir.live().exists());
    assert!(dir.root.join("old").exists());
    assert!(dir.stage().exists());
    dir.recover().unwrap();
    assert!(dir.live().exists());
    assert!(!dir.root.join("old").exists());
    assert!(!dir.stage().exists());
    assert_eq!(load_manifest(&dir).unwrap(), m1);

    // load_manifest recovers by itself.
    let schema = stage(&dir, &csv2);
    finish_crash_after_first_rename(&dir, &schema, 10, &key(), &mut ok, &mut |_| {}).unwrap();
    assert_eq!(load_manifest(&dir).unwrap(), m1);

    // And a complete second build replaces the first.
    let m2 = build(&dir, &csv2);
    assert_ne!(m2.snapshot_sha256, m1.snapshot_sha256);
    assert_eq!(load_manifest(&dir).unwrap(), m2);
    assert!(!dir.root.join("old").exists());
}

#[test]
fn stale_stage_is_removed() {
    let t = tempfile::tempdir().unwrap();
    let csv = fixture(t.path(), "csv", 200, 400, 3);
    let dir = ds(t.path());
    dir.clean_stage().unwrap(); // nothing there: fine

    // A killed build left a snapshot part and index runs.
    std::fs::create_dir_all(dir.stage()).unwrap();
    for f in [
        "snapshot.sqlite.part",
        "index.run.00ff.0",
        "index.run.00ff.1",
    ] {
        std::fs::write(dir.stage().join(f), b"half").unwrap();
    }
    let schema = stage(&dir, &csv);
    for f in [
        "snapshot.sqlite.part",
        "index.run.00ff.0",
        "index.run.00ff.1",
    ] {
        assert!(!dir.stage().join(f).exists(), "{f}");
    }
    finish(&dir, &schema, 10, &key(), &mut ok, &mut |_| {}).unwrap();

    // A symlinked stage: the link goes, its target is left alone.
    #[cfg(unix)]
    {
        let target = t.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.txt"), b"keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.stage()).unwrap();
        stage(&dir, &csv);
        assert!(target.join("keep.txt").exists());
        assert!(!target.join("snapshot.sqlite").exists());
        let md = std::fs::symlink_metadata(dir.stage()).unwrap();
        assert!(md.is_dir() && !md.file_type().is_symlink());
    }
}

#[test]
fn classes_come_from_schema() {
    let t = tempfile::tempdir().unwrap();
    let csv = fixture(t.path(), "csv", 300, 600, 4);
    let dir = ds(t.path());
    let schema = stage(&dir, &csv);

    for (tb, c) in [("customers", "email"), ("invoices", "amount")] {
        let mut bad = schema.clone();
        let ti = bad.tables.iter_mut().find(|x| x.name == tb).unwrap();
        ti.columns.iter_mut().find(|x| x.name == c).unwrap().class = ColumnClass::Public;
        let r = finish(&dir, &bad, 10, &key(), &mut ok, &mut |_| {});
        match r {
            Err(ShieldError::Corrupt(why)) => {
                assert_eq!(why, "a public column holds names, IDs or amounts")
            }
            other => panic!("{tb}.{c}: {other:?}"),
        }
        assert!(!dir.live().exists());
    }
    // k below 2 is refused.
    assert!(finish(&dir, &schema, 1, &key(), &mut ok, &mut |_| {}).is_err());
    // A schema that leaves out a snapshot column is refused.
    let mut short = schema.clone();
    short.tables[0].columns.pop();
    assert!(finish(&dir, &short, 10, &key(), &mut ok, &mut |_| {}).is_err());
    // The same stage still finishes with the right schema.
    finish(&dir, &schema, 10, &key(), &mut ok, &mut |_| {}).unwrap();
}

#[cfg(unix)]
#[test]
fn modes_are_tight() {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    let csv = fixture(t.path(), "csv", 300, 600, 5);
    let dir = ds(t.path());
    build(&dir, &csv);

    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            out.push(e.clone());
            if std::fs::symlink_metadata(&e).unwrap().is_dir() {
                walk(&e, out);
            }
        }
    }
    let mut all = vec![dir.root.clone()];
    walk(&dir.root, &mut all);
    for p in &all {
        let md = std::fs::symlink_metadata(p).unwrap();
        let mode = md.permissions().mode() & 0o777;
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!md.file_type().is_symlink(), "{name}");
        if md.is_dir() {
            assert_eq!(mode, 0o700, "{name}");
        } else if name == "manifest.json" {
            assert_eq!(mode, 0o600, "{name}");
        } else {
            assert_eq!(mode, 0o400, "{name}");
        }
        for bad in ["-journal", "-wal", "-shm", ".part", ".tmp"] {
            assert!(!name.ends_with(bad), "{name}");
        }
        assert!(!name.starts_with("index.run."), "{name}");
    }
    let mut top: Vec<String> = std::fs::read_dir(&dir.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, vec!["live"]);
    let mut live: Vec<String> = std::fs::read_dir(dir.live())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    live.sort();
    assert_eq!(
        live,
        vec![
            "allow.json",
            "index.bin",
            "index.bloom",
            "lexicon.sqlite",
            "manifest.json",
            "snapshot.sqlite"
        ]
    );

    // A loosened file mode is refused at load.
    let s = dir.snapshot();
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(load_manifest(&dir), Err(ShieldError::Corrupt(_))));
}
