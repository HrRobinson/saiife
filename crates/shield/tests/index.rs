//! Plan 43 T6: the keyed-hash known-value index, its Bloom filter and the
//! allow list. Every value here is made up.

use saiife_shield::index::{
    build_index, build_index_with_run_bytes, read_allow, split_phrases, write_allow, IndexKey,
    KnownIndex,
};
use saiife_shield::norm::normalize;
use saiife_shield::public::PublicValues;
use saiife_shield::schema::{ColType, ColumnClass, ColumnInfo, EntitySpec, Schema, TableInfo};
use saiife_shield::snapshot::build_snapshot;
use saiife_shield::source::{Cell, SourceTable, VecSource};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// A fake key from a fixed byte pattern (never a token-shaped literal).
fn key(seed: u8) -> IndexKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = seed.wrapping_mul(31).wrapping_add(i as u8);
    }
    IndexKey(Zeroizing::new(k))
}

fn t(s: &str) -> Cell {
    Cell::Text(s.into())
}

fn col(name: &str, ty: ColType, class: ColumnClass) -> ColumnInfo {
    ColumnInfo {
        name: name.into(),
        ty,
        class,
        alias: None,
    }
}

/// One table; `cols` must already be clean snapshot names.
fn one_table(name: &str, cols: Vec<ColumnInfo>, rows: u64, entity: bool) -> Schema {
    Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![TableInfo {
            name: name.into(),
            alias: Some("t1".into()),
            rows,
            columns: cols,
        }],
        entities: if entity {
            vec![EntitySpec {
                table: name.into(),
                key: "id".into(),
                names: vec!["first_name".into(), "last_name".into()],
                show: vec![],
                word: "customer".into(),
                word_da: "kunde".into(),
            }]
        } else {
            vec![]
        },
    }
}

/// Builds `dir/ds/snapshot.sqlite`; returns the dataset dir and the
/// snapshot path.
fn snapshot(dir: &Path, table: &str, cols: &[&str], rows: Vec<Vec<Cell>>) -> (PathBuf, PathBuf) {
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: table.into(),
                columns: cols.iter().map(|c| c.to_string()).collect(),
            },
            rows,
        )],
    };
    let ds = dir.join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    (ds, info.path)
}

const CUST: [(&str, ColType, ColumnClass); 7] = [
    ("id", ColType::Integer, ColumnClass::Identifier),
    ("first_name", ColType::Text, ColumnClass::Identifier),
    ("last_name", ColType::Text, ColumnClass::Identifier),
    ("email", ColType::Text, ColumnClass::Identifier),
    ("city", ColType::Text, ColumnClass::Quasi),
    ("status", ColType::Text, ColumnClass::Public),
    ("notes", ColType::Text, ColumnClass::FreeText),
];

fn cust_schema(rows: u64) -> Schema {
    one_table(
        "customers",
        CUST.iter().map(|(n, ty, c)| col(n, *ty, *c)).collect(),
        rows,
        true,
    )
}

/// The standard fixture: 3 rare people, 40 Mettes in Leeds, statuses that
/// pass the k-floor, and one rare last name equal to a status value.
fn standard_rows() -> Vec<Vec<Cell>> {
    let mut v: Vec<(&str, &str, String, &str, &str, &str)> = vec![
        (
            "Freja",
            "Lundqvist",
            "freja.lundqvist.1@example.invalid".into(),
            "Esbjerg",
            "open",
            "Met her twice. The lady who runs the bakery on main street! Paid.",
        ),
        (
            "Søren",
            "Ærø",
            "soeren.aeroe.2@example.invalid".into(),
            "Aalborg",
            "paid",
            "",
        ),
        // A rare last name that is also a public status value.
        (
            "Ida",
            "Open",
            "ida.open.3@example.invalid".into(),
            "Odense",
            "paid",
            "short note",
        ),
    ];
    for i in 0..40 {
        v.push((
            "Mette",
            "Hansen",
            format!("mette.hansen.{}@example.invalid", 10 + i),
            "Leeds",
            if i % 2 == 0 { "open" } else { "paid" },
            "",
        ));
    }
    v.into_iter()
        .enumerate()
        .map(|(i, (f, l, e, c, s, n))| {
            vec![
                Cell::Int(i as i64 + 4400),
                t(f),
                t(l),
                t(&e),
                t(c),
                t(s),
                t(n),
            ]
        })
        .collect()
}

fn standard_build(dir: &Path, k: u32) -> (PathBuf, PathBuf) {
    let cols: Vec<&str> = CUST.iter().map(|c| c.0).collect();
    let rows = standard_rows();
    let n = rows.len() as u64;
    let (ds, snap) = snapshot(dir, "customers", &cols, rows);
    build_index(&snap, &cust_schema(n), k, &key(1), &ds, &mut |_| {}).unwrap();
    (ds, snap)
}

#[test]
fn values_and_phrases_found() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    // A rare email and a rare name.
    assert!(ix
        .contains_value("freja.lundqvist.1@example.invalid")
        .unwrap());
    assert!(ix
        .contains_value("  FREJA.Lundqvist.1@example.invalid ")
        .unwrap());
    assert!(ix.contains_value("Lundqvist").unwrap());
    assert!(ix.contains_value("soeren").unwrap());
    assert!(ix.contains_value("Søren").unwrap());
    // The full name, either order.
    assert!(ix.contains_value("Freja Lundqvist").unwrap());
    assert!(ix.contains_value("Lundqvist, Freja").unwrap());
    // A note phrase, whole.
    assert!(ix
        .contains_phrase("the lady who runs the bakery on main street")
        .unwrap());
    assert!(ix
        .contains_phrase("The Lady who runs the bakery on Main Street")
        .unwrap());
    assert!(ix.contains_phrase("met her twice").unwrap());
    // A one-token sentence is not a phrase.
    assert!(!ix.contains_phrase("paid").unwrap());
    // Its single words do not hit, as a phrase or a value.
    for w in ["bakery", "lady", "street", "main street"] {
        assert!(!ix.contains_phrase(w).unwrap(), "{w}");
        assert!(!ix.contains_value(w).unwrap(), "{w}");
    }
    // A phrase is not a value and a value is not a phrase (the domains).
    assert!(!ix
        .contains_value("the lady who runs the bakery on main street")
        .unwrap());
    assert!(!ix.contains_phrase("lundqvist").unwrap());
    // Unknown things miss.
    assert!(!ix.contains_value("Zebulon").unwrap());
    assert!(!ix.contains_value("").unwrap());
    assert!(!ix.contains_phrase("").unwrap());
}

#[test]
fn numbers_and_dates_are_canonical() {
    let tmp = tempfile::tempdir().unwrap();
    let cols = ["id", "score", "born", "ref"];
    let schema = one_table(
        "people",
        vec![
            col("id", ColType::Integer, ColumnClass::Identifier),
            col("score", ColType::Real, ColumnClass::Quasi),
            col("born", ColType::Date, ColumnClass::Quasi),
            col("ref", ColType::Text, ColumnClass::Identifier),
        ],
        2,
        false,
    );
    let rows = vec![
        vec![
            Cell::Int(4411),
            Cell::Real(12.5),
            t("1980-05-03"),
            t("77.25"),
        ],
        vec![Cell::Int(98765), Cell::Real(3.0), t("1990-12-31"), t("x-1")],
    ];
    let (ds, snap) = snapshot(tmp.path(), "people", &cols, rows);
    build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    for s in ["4411", " 4411 ", "98765"] {
        assert!(ix.contains_value(s).unwrap(), "{s}");
    }
    // REAL: Rust's shortest round-trip text, so 12.50 and 12,5 hit too.
    for s in ["12.5", "12.50", "12,5", "3", "3.0"] {
        assert!(ix.contains_value(s).unwrap(), "{s}");
    }
    // A date in any of the snapshot's accepted spellings.
    for s in ["1980-05-03", "03.05.1980", "03/05/1980", "03-05-1980"] {
        assert!(ix.contains_value(s).unwrap(), "{s}");
    }
    // A number held as text is found by value.
    assert!(ix.contains_value("77.250").unwrap());
    assert!(!ix.contains_value("4412").unwrap());
    assert!(!ix.contains_value("4,411").unwrap());
}

#[test]
fn frequency_floor_excludes_common_values() {
    let tmp = tempfile::tempdir().unwrap();
    let cols = ["first_name", "city"];
    let schema = one_table(
        "people",
        vec![
            col("first_name", ColType::Text, ColumnClass::Identifier),
            col("city", ColType::Text, ColumnClass::Quasi),
        ],
        43,
        false,
    );
    let mut rows = Vec::new();
    for _ in 0..40 {
        rows.push(vec![t("Mette"), t("Leeds")]);
    }
    for _ in 0..3 {
        rows.push(vec![t("Thorvald"), t("Ærøskøbing")]);
    }
    let (ds, snap) = snapshot(tmp.path(), "people", &cols, rows);
    let stats = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    assert!(!ix.contains_value("Mette").unwrap());
    assert!(!ix.contains_value("Leeds").unwrap());
    assert!(ix.contains_value("Thorvald").unwrap());
    assert!(ix.contains_value("aeroeskoebing").unwrap());
    assert!(ix.contains_value("Aeroskobing").unwrap());
    assert_eq!(stats.left_out_common, 2);
    // Thorvald, aeroeskoebing and (I2) its ASCII-typed form aeroskobing.
    assert_eq!(stats.entries, 3);
    assert_eq!(stats.phrases, 0);
}

#[test]
fn allow_words_never_indexed() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let schema = cust_schema(43);
    let public = vec![PublicValues {
        column: "status".into(),
        passing: vec!["open".into(), "paid".into()],
        total_distinct: 2,
    }];
    let allow = write_allow(&schema, &public, &ds).unwrap();
    let back = read_allow(&ds.join("allow.json")).unwrap();
    assert_eq!(allow.words, back.words);
    for w in [
        "open",
        "paid",
        "status",
        "email",
        "first name",
        "customers",
        "t1",
    ] {
        assert!(back.words.contains(w), "{w}");
    }
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    // "Open" is a rare last name, but also a k-floor public value.
    for w in ["open", "Open", "paid", "status", "email", "customers"] {
        assert!(!ix.contains_value(w).unwrap(), "{w}");
    }
    // A rare value that is not an allow word is in.
    assert!(ix.contains_value("Ida").unwrap());
    // Values are stored normalized.
    for w in &back.words {
        assert_eq!(&normalize(w), w);
    }
    // A second write refuses (the file exists).
    assert!(write_allow(&schema, &public, &ds).is_err());
}

#[test]
fn bloom_false_positive_rate() {
    let tmp = tempfile::tempdir().unwrap();
    let n = 100_000u64;
    let rows: Vec<Vec<Cell>> = (0..n).map(|i| vec![t(&format!("zq{i}w"))]).collect();
    let (ds, snap) = snapshot(tmp.path(), "codes", &["code"], rows);
    let schema = one_table(
        "codes",
        vec![col("code", ColType::Text, ColumnClass::Identifier)],
        n,
        false,
    );
    let stats = build_index(&snap, &schema, 10, &key(2), &ds, &mut |_| {}).unwrap();
    assert_eq!(stats.entries, n);
    let ix = KnownIndex::open(&ds, key(2)).unwrap();
    for i in (0..n).step_by(997) {
        assert!(ix.contains_value(&format!("zq{i}w")).unwrap());
    }
    let (mut bloom, mut found) = (0u64, 0u64);
    let misses = 100_000u64;
    for i in 0..misses {
        let s = format!("miss{i}x");
        if ix.bloom_may_contain_value(&s) {
            bloom += 1;
        }
        if ix.contains_value(&s).unwrap() {
            found += 1;
        }
    }
    // < 0.05 % of 100 000 is < 50.
    assert!(bloom < 50, "bloom false positives: {bloom}");
    assert!(found < 50, "false positives after the search: {found}");
}

#[test]
fn different_key_misses() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let ix = KnownIndex::open(&ds, key(9)).unwrap();
    for s in [
        "Freja",
        "Lundqvist",
        "freja.lundqvist.1@example.invalid",
        "4400",
    ] {
        assert!(!ix.contains_value(s).unwrap(), "{s}");
    }
    assert!(!ix
        .contains_phrase("the lady who runs the bakery on main street")
        .unwrap());
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Many rare values: forces several 4 KiB runs.
fn many_rows(n: usize) -> (Vec<Vec<Cell>>, Schema) {
    let rows = (0..n)
        .map(|i| {
            vec![
                t(&format!("vq{i}name")),
                t(&format!(
                    "note number {i} for the file. second part {i} here"
                )),
            ]
        })
        .collect();
    let schema = one_table(
        "things",
        vec![
            col("name", ColType::Text, ColumnClass::Identifier),
            col("notes", ColType::Text, ColumnClass::FreeText),
        ],
        n as u64,
        false,
    );
    (rows, schema)
}

#[test]
fn external_sort_runs() {
    let tmp = tempfile::tempdir().unwrap();
    // 18 000 entries in 4 KiB runs: over 64 runs, so the merge takes two passes.
    let (rows, schema) = many_rows(6000);
    let (ds, snap) = snapshot(tmp.path(), "things", &["name", "notes"], rows);
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let sa = build_index(&snap, &schema, 10, &key(3), &a, &mut |_| {}).unwrap();
    let mut calls = 0u32;
    let sb = build_index_with_run_bytes(&snap, &schema, 10, &key(3), &b, &mut |_| calls += 1, 4096)
        .unwrap();
    assert!(calls > 10, "the small run size must give many runs");
    assert_eq!((sa.entries, sa.phrases), (sb.entries, sb.phrases));
    assert_eq!(sa.entries, 18000);
    assert!(calls > 64, "more runs than one merge pass takes");
    for f in ["index.bin", "index.bloom"] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
    // No run or part files are left.
    assert_eq!(file_names(&b), vec!["index.bin", "index.bloom"]);
    let ix = KnownIndex::open(&b, key(3)).unwrap();
    assert!(ix.contains_value("vq2999name").unwrap());
    assert!(ix.contains_phrase("second part 17 here").unwrap());
    assert!(ix.contains_phrase("note number 1234 for the file").unwrap());
    let _ = ds;
}

#[test]
fn duplicates_are_merged() {
    let tmp = tempfile::tempdir().unwrap();
    // The same phrase in 500 cells, across many runs: one entry.
    let rows: Vec<Vec<Cell>> = (0..500)
        .map(|i| vec![t(&format!("rare{i}")), t("called about the late invoice")])
        .collect();
    let schema = one_table(
        "things",
        vec![
            col("name", ColType::Text, ColumnClass::Identifier),
            col("notes", ColType::Text, ColumnClass::FreeText),
        ],
        500,
        false,
    );
    let (_, snap) = snapshot(tmp.path(), "things", &["name", "notes"], rows);
    let out = tmp.path().join("o");
    let s =
        build_index_with_run_bytes(&snap, &schema, 10, &key(3), &out, &mut |_| {}, 4096).unwrap();
    assert_eq!(s.entries, 501);
    assert_eq!(s.phrases, 500);
    let len = std::fs::metadata(out.join("index.bin")).unwrap().len();
    assert_eq!(len, 32 + 16 * 501);
}

#[test]
fn no_run_files_after_a_failing_build() {
    let tmp = tempfile::tempdir().unwrap();
    let (rows, mut schema) = many_rows(2000);
    let (_, snap) = snapshot(tmp.path(), "things", &["name", "notes"], rows);
    // A column the snapshot lacks, after columns that fill many runs: the
    // read fails mid-build.
    schema.tables[0]
        .columns
        .push(col("missing", ColType::Text, ColumnClass::Identifier));
    let out = tmp.path().join("o");
    let mut calls = 0u32;
    let r =
        build_index_with_run_bytes(&snap, &schema, 10, &key(4), &out, &mut |_| calls += 1, 4096);
    assert!(r.is_err());
    assert!(calls > 5, "runs were written before the failure");
    assert!(file_names(&out).is_empty(), "{:?}", file_names(&out));

    // A panic in the progress callback mid-build: the guards still clean up.
    schema.tables[0].columns.pop();
    let out2 = tmp.path().join("o2");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut n = 0u32;
        build_index_with_run_bytes(
            &snap,
            &schema,
            10,
            &key(4),
            &out2,
            &mut |_| {
                n += 1;
                if n == 4 {
                    panic!("injected");
                }
            },
            4096,
        )
    }));
    assert!(r.is_err());
    assert!(file_names(&out2).is_empty(), "{:?}", file_names(&out2));
}

#[test]
fn error_texts_hold_no_values() {
    let tmp = tempfile::tempdir().unwrap();
    let (rows, mut schema) = many_rows(50);
    let (_, snap) = snapshot(tmp.path(), "things", &["name", "notes"], rows);
    schema.tables[0]
        .columns
        .push(col("missing", ColType::Text, ColumnClass::Identifier));
    let e = build_index(
        &snap,
        &schema,
        10,
        &key(4),
        &tmp.path().join("o"),
        &mut |_| {},
    )
    .unwrap_err()
    .to_string();
    assert!(!e.contains("vq"), "{e}");
    assert!(!e.contains("note number"), "{e}");
    assert_eq!(format!("{:?}", key(4)), "IndexKey(..)");
}

#[test]
fn no_plaintext_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let mut bytes = std::fs::read(ds.join("index.bin")).unwrap();
    bytes.extend(std::fs::read(ds.join("index.bloom")).unwrap());
    let needles = [
        "Freja",
        "freja",
        "Lundqvist",
        "lundqvist",
        "Søren",
        "soeren",
        "Esbjerg",
        "esbjerg",
        "bakery",
        "example.invalid",
        "4400",
    ];
    for n in needles {
        let nb = n.as_bytes();
        assert!(!bytes.windows(nb.len()).any(|w| w == nb), "{n} on disk");
    }
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    let dbg = format!("{ix:?}");
    assert!(!dbg.to_lowercase().contains("freja"), "{dbg}");
}

#[test]
fn empty_index_is_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let cols = ["first_name"];
    let schema = one_table(
        "people",
        vec![col("first_name", ColType::Text, ColumnClass::Identifier)],
        20,
        false,
    );
    let rows = (0..20).map(|_| vec![t("Mette")]).collect();
    let (ds, snap) = snapshot(tmp.path(), "people", &cols, rows);
    let s = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    assert_eq!(s.entries, 0);
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    assert!(!ix.contains_value("Mette").unwrap());
    assert!(!ix.contains_value("anything").unwrap());
    assert!(!ix.contains_phrase("one two three").unwrap());
}

#[test]
fn corrupt_files_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let copy = tmp.path().join("copy");
    std::fs::create_dir(&copy).unwrap();
    let bin = std::fs::read(ds.join("index.bin")).unwrap();
    let bloom = std::fs::read(ds.join("index.bloom")).unwrap();
    // A truncated index.
    std::fs::write(copy.join("index.bin"), &bin[..bin.len() - 3]).unwrap();
    std::fs::write(copy.join("index.bloom"), &bloom).unwrap();
    assert!(KnownIndex::open(&copy, key(1)).is_err());
    // A bad magic.
    let mut b2 = bin.clone();
    b2[0] = b'X';
    std::fs::write(copy.join("index.bin"), &b2).unwrap();
    assert!(KnownIndex::open(&copy, key(1)).is_err());
    // A bloom of the wrong size.
    std::fs::write(copy.join("index.bin"), &bin).unwrap();
    std::fs::write(copy.join("index.bloom"), &bloom[..bloom.len() - 8]).unwrap();
    assert!(KnownIndex::open(&copy, key(1)).is_err());
    // A corrupt allow list.
    std::fs::write(
        copy.join("allow.json"),
        b"{\"version\":1,\"words\":[\"Not Normal\"]}",
    )
    .unwrap();
    assert!(read_allow(&copy.join("allow.json")).is_err());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn files_are_sealed_0400() {
        let tmp = tempfile::tempdir().unwrap();
        let (ds, _) = standard_build(tmp.path(), 10);
        write_allow(&cust_schema(43), &[], &ds).unwrap();
        for f in ["index.bin", "index.bloom", "allow.json"] {
            assert_eq!(mode(&ds.join(f)), 0o400, "{f}");
        }
        assert_eq!(mode(&ds), 0o700);
        let names = file_names(&ds);
        assert!(names
            .iter()
            .all(|n| !n.contains(".part") && !n.contains("run")));
    }

    #[test]
    fn symlink_at_a_part_path_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let cols: Vec<&str> = CUST.iter().map(|c| c.0).collect();
        let (ds, snap) = snapshot(tmp.path(), "customers", &cols, standard_rows());
        let target = tmp.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, ds.join("index.bin.part")).unwrap();
        let r = build_index(&snap, &cust_schema(43), 10, &key(1), &ds, &mut |_| {});
        assert!(r.is_err());
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(ds.join("index.bin")).is_err());
        std::fs::remove_file(ds.join("index.bin.part")).unwrap();

        std::os::unix::fs::symlink(&target, ds.join("index.bloom.part")).unwrap();
        let r = build_index(&snap, &cust_schema(43), 10, &key(1), &ds, &mut |_| {});
        assert!(r.is_err());
        assert!(!target.exists());
        // A failed bloom leaves no index behind: a retry can run.
        assert!(std::fs::symlink_metadata(ds.join("index.bin")).is_err());
        std::fs::remove_file(ds.join("index.bloom.part")).unwrap();
        build_index(&snap, &cust_schema(43), 10, &key(1), &ds, &mut |_| {}).unwrap();

        std::os::unix::fs::symlink(&target, ds.join("allow.json.part")).unwrap();
        assert!(write_allow(&cust_schema(43), &[], &ds).is_err());
        assert!(!target.exists());

        // A symlinked index file is not followed on open.
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(ds.join("index.bin"), other.join("index.bin")).unwrap();
        std::fs::copy(ds.join("index.bloom"), other.join("index.bloom")).unwrap();
        assert!(KnownIndex::open(&other, key(1)).is_err());
    }
}

// ------------------------------------------------------ fix round 1 ----

#[test]
fn phrase_lookup_splits_like_the_build() {
    let tmp = tempfile::tempdir().unwrap();
    let (ds, _) = standard_build(tmp.path(), 10);
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    // R-15: a whole sentence with a known phrase in it hits.
    assert!(ix
        .contains_phrase("x y z; the lady who runs the bakery on main street")
        .unwrap());
    assert!(ix
        .contains_phrase("Hi. The lady who runs the bakery on main street! Bye now")
        .unwrap());
    // The whole normalized input is tried too.
    assert!(ix.contains_phrase("met her twice").unwrap());
    // Single words still miss.
    for w in ["bakery", "lady", "street"] {
        assert!(!ix.contains_phrase(w).unwrap(), "{w}");
    }
    assert_eq!(
        split_phrases("one two. Three four five!\nsix seven eight nine; ten"),
        vec!["three four five", "six seven eight nine"]
    );
    let long = vec!["w"; 41].join(" ");
    assert!(split_phrases(&long).is_empty());
}

/// An entity table where one customer (key 1) has 20 invoice rows and 12
/// other customers share a first name.
fn denormalized_rows() -> Vec<Vec<Cell>> {
    let mut rows = Vec::new();
    for _ in 0..20 {
        rows.push(vec![
            Cell::Int(1),
            t("Ingeborg"),
            t("Quistgaard"),
            t("ingeborg.quistgaard.1@example.invalid"),
        ]);
    }
    for i in 0..12 {
        rows.push(vec![
            Cell::Int(100 + i),
            t("Mette"),
            t(&format!("Zz{i}son")),
            t(&format!("m{i}@example.invalid")),
        ]);
    }
    rows
}

#[test]
fn floor_counts_people_not_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let cols = ["id", "first_name", "last_name", "email"];
    let schema = one_table(
        "customers",
        vec![
            col("id", ColType::Integer, ColumnClass::Identifier),
            col("first_name", ColType::Text, ColumnClass::Identifier),
            col("last_name", ColType::Text, ColumnClass::Identifier),
            col("email", ColType::Text, ColumnClass::Identifier),
        ],
        32,
        true,
    );
    let (ds, snap) = snapshot(tmp.path(), "customers", &cols, denormalized_rows());
    build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    // R-14: one person in 20 rows is one record.
    assert!(ix.contains_value("Quistgaard").unwrap());
    assert!(ix
        .contains_value("ingeborg.quistgaard.1@example.invalid")
        .unwrap());
    assert!(ix.contains_value("Ingeborg Quistgaard").unwrap());
    // Twelve people share "Mette": common.
    assert!(!ix.contains_value("Mette").unwrap());
    assert!(ix.contains_value("Zz3son").unwrap());

    // The same rows in a table with no entity count rows.
    let tmp2 = tempfile::tempdir().unwrap();
    let mut plain = schema.clone();
    plain.entities.clear();
    let (ds2, snap2) = snapshot(tmp2.path(), "customers", &cols, denormalized_rows());
    build_index(&snap2, &plain, 10, &key(1), &ds2, &mut |_| {}).unwrap();
    let ix2 = KnownIndex::open(&ds2, key(1)).unwrap();
    assert!(!ix2.contains_value("Quistgaard").unwrap());
}

#[test]
fn digit_groupings_match() {
    let tmp = tempfile::tempdir().unwrap();
    let cols = ["phone", "ref"];
    let schema = one_table(
        "people",
        vec![
            col("phone", ColType::Text, ColumnClass::Identifier),
            col("ref", ColType::Text, ColumnClass::Identifier),
        ],
        2,
        false,
    );
    let rows = vec![
        vec![t("12 34 56 78"), t("010180-1234")],
        vec![t("87654321"), t("x-9")],
    ];
    let (ds, snap) = snapshot(tmp.path(), "people", &cols, rows);
    build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    for s in [
        "12 34 56 78",
        "12345678",
        "12-34-56-78",
        "010180-1234",
        "0101801234",
        "87654321",
        "87 65 43 21",
        "8765.4321",
    ] {
        assert!(ix.contains_value(s).unwrap(), "{s}");
    }
    assert!(!ix.contains_value("12345679").unwrap());
}

#[test]
fn floor_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let schema = one_table(
        "people",
        vec![col("first_name", ColType::Text, ColumnClass::Identifier)],
        21,
        false,
    );
    let mut rows: Vec<Vec<Cell>> = (0..10).map(|_| vec![t("Kirsten")]).collect();
    rows.extend((0..11).map(|_| vec![t("Valdemar")]));
    let (ds, snap) = snapshot(tmp.path(), "people", &["first_name"], rows);
    let s = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    assert!(ix.contains_value("Kirsten").unwrap(), "exactly k: in");
    assert!(!ix.contains_value("Valdemar").unwrap(), "k + 1: out");
    assert_eq!(s.left_out_common, 1);
}

/// R43-10: a schema word never enters the index, even as a rare real value.
/// The firewall passes schema words, so the index would not stop it anyway.
#[test]
fn rare_value_equal_to_a_column_name_is_not_indexed() {
    let tmp = tempfile::tempdir().unwrap();
    let schema = one_table(
        "people",
        vec![
            col("last_name", ColType::Text, ColumnClass::Identifier),
            col("email", ColType::Text, ColumnClass::Identifier),
        ],
        2,
        false,
    );
    let rows = vec![
        vec![t("Email"), t("a.1@example.invalid")],
        vec![t("Brorson"), t("b.2@example.invalid")],
    ];
    let (ds, snap) = snapshot(tmp.path(), "people", &["last_name", "email"], rows);
    build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    assert!(!ix.contains_value("Email").unwrap());
    assert!(ix.contains_value("Brorson").unwrap());
}

#[test]
fn progress_never_goes_back() {
    let tmp = tempfile::tempdir().unwrap();
    let rows: Vec<Vec<Cell>> = (0..500)
        .map(|i| vec![t(&format!("rare{i}")), t("called about the late invoice")])
        .collect();
    let schema = one_table(
        "things",
        vec![
            col("name", ColType::Text, ColumnClass::Identifier),
            col("notes", ColType::Text, ColumnClass::FreeText),
        ],
        500,
        false,
    );
    let (_, snap) = snapshot(tmp.path(), "things", &["name", "notes"], rows);
    let mut seen: Vec<u64> = Vec::new();
    build_index_with_run_bytes(
        &snap,
        &schema,
        10,
        &key(3),
        &tmp.path().join("o"),
        &mut |n| seen.push(n),
        4096,
    )
    .unwrap();
    assert!(seen.len() > 2);
    assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{seen:?}");
}

#[test]
fn a_public_values_error_fails_the_build() {
    let tmp = tempfile::tempdir().unwrap();
    // `credit_limit` is an amount name: public_values refuses it.
    let schema = one_table(
        "people",
        vec![
            col("first_name", ColType::Text, ColumnClass::Identifier),
            col("credit_limit", ColType::Text, ColumnClass::Public),
        ],
        12,
        false,
    );
    let rows = (0..12)
        .map(|i| vec![t(&format!("Nm{i}")), t("high")])
        .collect();
    let (ds, snap) = snapshot(tmp.path(), "people", &["first_name", "credit_limit"], rows);
    let e = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("credit_limit"), "{msg}");
    assert!(!msg.contains("high"), "{msg}");
}

/// I2: a Danish name typed in ASCII (`ø` as `o`, `å` as `a`) still hits.
#[test]
fn danish_name_typed_in_ascii_hits() {
    let tmp = tempfile::tempdir().unwrap();
    let schema = one_table(
        "people",
        vec![col("name", ColType::Text, ColumnClass::Identifier)],
        2,
        false,
    );
    let rows = vec![vec![t("Søren Ærø")], vec![t("Åse Blåbær")]];
    let (ds, snap) = snapshot(tmp.path(), "people", &["name"], rows);
    build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    for q in [
        "Soren Aero",
        "soeren aeroe",
        "Søren Ærø",
        "Aero Soren",
        "Ase Blabaer",
        "aase blaabaer",
    ] {
        assert!(ix.contains_value(q).unwrap(), "{q}");
    }
    assert!(!ix.contains_value("Soren Aaro").unwrap());
}

/// I3: a value of 5 or more tokens is also found by any 4-token window
/// (plan 44 scans 2 to 4 tokens), under the same floor as the whole value.
#[test]
fn long_values_are_found_by_four_token_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let schema = one_table(
        "people",
        vec![
            col("address", ColType::Text, ColumnClass::Quasi),
            col("street", ColType::Text, ColumnClass::Quasi),
        ],
        41,
        false,
    );
    let mut rows = vec![vec![t("Strandvejen 12 2 th 8000 Aarhus C"), t("Kystvej 1")]];
    for _ in 0..40 {
        rows.push(vec![t("Fjordgade 7 1 tv 9000 Aalborg"), t("Kystvej 1")]);
    }
    let (ds, snap) = snapshot(tmp.path(), "people", &["address", "street"], rows);
    let stats = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    let ix = KnownIndex::open(&ds, key(1)).unwrap();
    assert!(ix
        .contains_value("Strandvejen 12 2 th 8000 Aarhus C")
        .unwrap());
    assert!(ix.contains_value("12 2 th 8000").unwrap());
    assert!(ix.contains_value("2 th 8000 Aarhus").unwrap());
    // The common address is over the floor: neither it nor its windows.
    assert!(!ix.contains_value("7 1 tv 9000").unwrap());
    assert_eq!(stats.max_value_tokens, 7);
}

/// M6 / R-19: a free-text piece of more than 40 tokens is not indexed, but
/// counted.
#[test]
fn over_long_phrases_are_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let schema = one_table(
        "notes",
        vec![col("notes", ColType::Text, ColumnClass::FreeText)],
        1,
        false,
    );
    let long: Vec<String> = (0..45).map(|i| format!("w{i}")).collect();
    let note = format!("{}. one two three", long.join(" "));
    let (ds, snap) = snapshot(tmp.path(), "notes", &["notes"], vec![vec![t(&note)]]);
    let stats = build_index(&snap, &schema, 10, &key(1), &ds, &mut |_| {}).unwrap();
    assert_eq!(stats.phrases, 1);
    assert_eq!(stats.phrases_too_long, 1);
}
