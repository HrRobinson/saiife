//! Plan 43 T5: normalization, the lexicon, entity resolution and "did you
//! mean". Every name here is made up.

#[path = "fixtures.rs"]
mod fixtures;

use saiife_shield::lexicon::{build_lexicon, Candidate, Lexicon, Resolve, SpanHit};
use saiife_shield::norm::{normalize, sorted_key, tokens};
use saiife_shield::schema::{ColType, ColumnClass, ColumnInfo, EntitySpec, Schema, TableInfo};
use saiife_shield::snapshot::build_snapshot;
use saiife_shield::source::{Cell, SourceTable, VecSource};
use std::path::{Path, PathBuf};

const COLS: [(&str, ColType, ColumnClass); 6] = [
    ("id", ColType::Integer, ColumnClass::Identifier),
    ("first_name", ColType::Text, ColumnClass::Identifier),
    ("last_name", ColType::Text, ColumnClass::Identifier),
    ("city", ColType::Text, ColumnClass::Quasi),
    ("segment", ColType::Text, ColumnClass::Public),
    ("notes", ColType::Text, ColumnClass::FreeText),
];

fn schema(rows: u64) -> Schema {
    Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![TableInfo {
            name: "customers".into(),
            alias: None,
            rows,
            columns: COLS
                .iter()
                .map(|(n, ty, class)| ColumnInfo {
                    name: (*n).into(),
                    ty: *ty,
                    class: *class,
                    alias: None,
                })
                .collect(),
        }],
        entities: vec![EntitySpec {
            table: "customers".into(),
            key: "id".into(),
            names: vec!["first_name".into(), "last_name".into()],
            show: vec!["city".into()],
            word: "customer".into(),
            word_da: "kunde".into(),
        }],
    }
}

fn t(s: &str) -> Cell {
    Cell::Text(s.into())
}

/// (first, last, city): ids are 1, 2, 3, ... in order.
fn rows(names: &[(&str, &str, &str)]) -> Vec<Vec<Cell>> {
    names
        .iter()
        .enumerate()
        .map(|(i, (f, l, c))| {
            vec![
                Cell::Int(i as i64 + 1),
                t(f),
                t(l),
                t(c),
                t("retail"),
                t("zzfreetext note"),
            ]
        })
        .collect()
}

/// Builds `ds/snapshot.sqlite` and `ds/lexicon.sqlite`; returns the lexicon
/// path.
fn build_from(dir: &Path, rows: Vec<Vec<Cell>>) -> PathBuf {
    let n = rows.len() as u64;
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: COLS.iter().map(|c| c.0.to_string()).collect(),
            },
            rows,
        )],
    };
    let ds = dir.join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let lex = ds.join("lexicon.sqlite");
    build_lexicon(&info.path, &schema(n), &lex).unwrap();
    lex
}

/// The standard small fixture.
fn standard(dir: &Path) -> Lexicon {
    let mut names: Vec<(&str, &str, &str)> = vec![
        ("Anna", "Berg", "Aarhus"),
        ("Anna", "Berg", "Odense"),
        ("Søren", "Ærø", "Aalborg"),
        ("Freja", "Lund", "Esbjerg"),
        ("Ida", "Bo", "Odense"),
    ];
    for _ in 0..25 {
        names.push(("Mette", "Hansen", "Leeds"));
    }
    Lexicon::open(&build_from(dir, rows(&names))).unwrap()
}

fn cities(v: &[Candidate]) -> Vec<String> {
    v.iter()
        .map(|c| {
            assert_eq!(c.show.len(), 1);
            assert_eq!(c.show[0].0, "city");
            c.show[0].1.clone()
        })
        .collect()
}

#[test]
fn normalize_rules() {
    assert_eq!(normalize("Søren  ÆRØ"), "soeren aeroe");
    assert_eq!(normalize("Åse-Østergård"), "aase oestergaard");
    assert_eq!(normalize("Anna Berg"), normalize("anna  berg "));
    assert_eq!(normalize("Anna Berg"), "anna berg");
    assert_eq!(normalize("Straße"), "strasse");
    assert_eq!(normalize("Ze\u{301}lie  O'Brien"), "zelie o brien");
    // A decomposed Å (A + ring) folds like the composed one.
    assert_eq!(normalize("A\u{30a}se"), "aase");
    assert_eq!(normalize("  ,; "), "");
    assert_eq!(tokens("Berg, Anna"), vec!["berg", "anna"]);
    assert_eq!(sorted_key("Berg, Anna"), "anna berg");
    assert_eq!(sorted_key("Anna Berg"), sorted_key("berg anna"));
    // Initials are not expanded in stage 1.
    assert_ne!(sorted_key("A. Berg"), sorted_key("Anna Berg"));
    // Normalizing is idempotent.
    let n = normalize("Ærø, Søren");
    assert_eq!(normalize(&n), n);
}

#[test]
fn resolve_one_many_none() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    let (r, too_many) = lex.resolve("customers", "Anna Berg").unwrap();
    assert!(!too_many);
    let Resolve::Many(v) = r else {
        panic!("expected Many")
    };
    assert_eq!(v.len(), 2);
    assert_eq!(v.iter().map(|c| c.key).collect::<Vec<_>>(), vec![1, 2]);
    assert!(v.iter().all(|c| c.table == "customers"));
    assert!(v.iter().all(|c| c.display == "Anna Berg"));
    assert_eq!(cities(&v), vec!["Aarhus", "Odense"]);

    let (r, too_many) = lex.resolve("customers", "Søren Ærø").unwrap();
    assert!(!too_many);
    let Resolve::One(c) = r else {
        panic!("expected One")
    };
    assert_eq!((c.key, c.display.as_str()), (3, "Søren Ærø"));
    assert_eq!(cities(&[c]), vec!["Aalborg"]);

    let (r, too_many) = lex.resolve("customers", "Nobody Here").unwrap();
    assert_eq!(r, Resolve::None);
    assert!(!too_many);
    assert_eq!(lex.resolve("customers", "  ").unwrap().0, Resolve::None);
    assert_eq!(lex.resolve("orders", "Anna Berg").unwrap().0, Resolve::None);
}

#[test]
fn name_order_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    for q in ["Berg, Anna", "berg anna", "ANNA   BERG"] {
        let (r, _) = lex.resolve("customers", q).unwrap();
        let Resolve::Many(v) = r else {
            panic!("expected Many")
        };
        assert_eq!(v.iter().map(|c| c.key).collect::<Vec<_>>(), vec![1, 2]);
    }
}

#[test]
fn danish_variants_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    for q in ["Soeren Aeroe", "Ærø, Søren", "SØREN ÆRØ", "soeren-aeroe"] {
        let (r, _) = lex.resolve("customers", q).unwrap();
        let Resolve::One(c) = r else {
            panic!("expected One")
        };
        assert_eq!(c.key, 3);
    }
}

#[test]
fn danish_ascii_fold_is_suggested() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    // Not equal ...
    assert_eq!(
        lex.resolve("customers", "soren aero").unwrap().0,
        Resolve::None
    );
    // ... but the one suggestion.
    let c = lex
        .did_you_mean("soren aero")
        .unwrap()
        .expect("a suggestion");
    assert_eq!((c.key, c.display.as_str()), (3, "Søren Ærø"));
    assert_eq!(c.table, "customers");
    assert_eq!(cities(&[c]), vec!["Aalborg"]);
}

#[test]
fn typo_suggested_once() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    let c = lex.did_you_mean("Ana Berg").unwrap().expect("a suggestion");
    assert_eq!(c.display, "Anna Berg");
    assert!(c.key == 1 || c.key == 2);
    // Name order does not hide a typo.
    let c = lex
        .did_you_mean("Berg, Ana")
        .unwrap()
        .expect("a suggestion");
    assert_eq!(c.display, "Anna Berg");
    // Too far: 3 edits.
    assert!(lex.did_you_mean("Annika Bergen").unwrap().is_none());
    // Over 25 % of a short query: "idx bx" (6 chars, limit 1) is 2 from
    // "ida bo"; "ida bx" is 1.
    assert!(lex.did_you_mean("Idx Bx").unwrap().is_none());
    assert_eq!(lex.did_you_mean("Ida Bx").unwrap().unwrap().key, 5);
    assert!(lex.did_you_mean("").unwrap().is_none());

    // Two equally close names: no guess.
    let dir = tempfile::tempdir().unwrap();
    let lex = Lexicon::open(&build_from(
        dir.path(),
        rows(&[("Anna", "Berg", "Aarhus"), ("Anne", "Berg", "Odense")]),
    ))
    .unwrap();
    assert!(lex.did_you_mean("Ann Berg").unwrap().is_none());
    // One closest still wins.
    let c = lex
        .did_you_mean("Anna Bergg")
        .unwrap()
        .expect("a suggestion");
    assert_eq!(c.key, 1);
}

#[test]
fn spans_in_question() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    let q = "What does Anna Berg in Aarhus owe?";
    let spans = lex.find_spans(q, 4).unwrap();
    assert_eq!(spans.len(), 2, "{spans:?}");
    match &spans[0] {
        SpanHit::Entity { start, end, table } => {
            assert_eq!(&q[*start..*end], "Anna Berg");
            assert_eq!(table, "customers");
        }
        other => panic!("expected an entity span, got {other:?}"),
    }
    match &spans[1] {
        SpanHit::Literal { start, end, hit } => {
            assert_eq!(&q[*start..*end], "Aarhus");
            assert_eq!(hit.column, ("customers".to_string(), "city".to_string()));
            assert_eq!(hit.value, "Aarhus");
            assert_eq!(hit.count, 1);
        }
        other => panic!("expected a literal span, got {other:?}"),
    }

    // Offsets are bytes of the question, across non-ASCII text and name order.
    let q = "Hvad skylder Ærø, Søren i Leeds?";
    let spans = lex.find_spans(q, 4).unwrap();
    assert_eq!(spans.len(), 2, "{spans:?}");
    let SpanHit::Entity { start, end, .. } = &spans[0] else {
        panic!("expected an entity span")
    };
    assert_eq!(&q[*start..*end], "Ærø, Søren");
    let SpanHit::Literal { start, end, hit } = &spans[1] else {
        panic!("expected a literal span")
    };
    assert_eq!(&q[*start..*end], "Leeds");
    assert_eq!(hit.count, 25);

    // Public columns are literals; free text is not.
    let spans = lex.find_spans("retail zzfreetext note", 4).unwrap();
    assert_eq!(spans.len(), 1, "{spans:?}");
    let SpanHit::Literal { hit, .. } = &spans[0] else {
        panic!("expected a literal span")
    };
    assert_eq!(hit.column.1, "segment");
    // A span longer than max_tokens is not found.
    assert!(lex.find_spans("Søren Ærø", 1).unwrap().is_empty());
}

#[test]
fn candidates_capped() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    let (r, too_many) = lex.resolve("customers", "Mette Hansen").unwrap();
    assert!(too_many);
    let Resolve::Many(v) = r else {
        panic!("expected Many")
    };
    assert_eq!(v.len(), 20);
    assert!(v.iter().all(|c| c.display == "Mette Hansen"));
}

#[test]
fn prefix_search_capped() {
    // 50 001 distinct names share the prefix "an" with the query, plus the
    // one name the query is a typo of: over the cap gives no suggestion.
    let mut r = fixtures::Rng::new(43);
    let mut rs = rows(&[("Anna", "Berg", "Aarhus"), ("Zora", "Berg", "Aarhus")]);
    let letters: Vec<char> = ('a'..='z').collect();
    for i in 0..50_001u64 {
        let mut last = String::from("Q");
        let mut k = i;
        for _ in 0..4 {
            last.push(letters[(k % 26) as usize]);
            k /= 26;
        }
        last.push(letters[r.below(26) as usize]);
        rs.push(vec![
            Cell::Int(i as i64 + 3),
            t("Anders"),
            t(&last),
            t("Leeds"),
            t("vip"),
            Cell::Null,
        ]);
    }
    let dir = tempfile::tempdir().unwrap();
    let lex = Lexicon::open(&build_from(dir.path(), rs)).unwrap();
    assert!(lex.did_you_mean("Anna Bergx").unwrap().is_none());
    // Exact resolution is not affected by the cap.
    assert!(matches!(
        lex.resolve("customers", "Anna Berg").unwrap().0,
        Resolve::One(_)
    ));
    // A query whose prefixes ("zo", "be") stay under the cap still gets
    // its suggestion.
    let c = lex
        .did_you_mean("Zora Bergx")
        .unwrap()
        .expect("a suggestion");
    assert_eq!(c.key, 2);
}

#[test]
fn errors_and_debug_carry_no_names() {
    let dir = tempfile::tempdir().unwrap();
    let lex = standard(dir.path());
    let (r, _) = lex.resolve("customers", "Søren Ærø").unwrap();
    let dbg = format!("{r:?}");
    assert!(!dbg.contains("Søren"), "{dbg}");
    assert!(!dbg.contains("Aalborg"), "{dbg}");
    let spans = lex.find_spans("Anna Berg in Aarhus", 4).unwrap();
    let dbg = format!("{spans:?}");
    assert!(!dbg.contains("Aarhus"), "{dbg}");

    // A key that is not an integer refuses, naming only table and column.
    let dir = tempfile::tempdir().unwrap();
    let mut rs = rows(&[("Anna", "Berg", "Aarhus")]);
    rs[0][0] = t("Zebulon");
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: COLS.iter().map(|c| c.0.to_string()).collect(),
            },
            rs,
        )],
    };
    let ds = dir.path().join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let e = build_lexicon(&info.path, &schema(1), &ds.join("lexicon.sqlite")).unwrap_err();
    let text = format!("{e} {e:?}");
    assert!(text.contains("customers") && text.contains("id"), "{text}");
    for v in ["Zebulon", "Anna", "Berg", "Aarhus"] {
        assert!(!text.contains(v), "{text}");
    }
    // No part file and no lexicon remain after a failed build.
    let left: Vec<String> = std::fs::read_dir(&ds)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["snapshot.sqlite".to_string()]);
}

#[cfg(unix)]
#[test]
fn lexicon_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let lex = build_from(dir.path(), rows(&[("Anna", "Berg", "Aarhus")]));
    let md = std::fs::symlink_metadata(&lex).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o400);
    let mut names: Vec<String> = std::fs::read_dir(lex.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["lexicon.sqlite", "snapshot.sqlite"]);
    // Opening read-only leaves no side files either.
    let l = Lexicon::open(&lex).unwrap();
    let _ = l.resolve("customers", "Anna Berg").unwrap();
    let _ = l.did_you_mean("Ana Berg").unwrap();
    drop(l);
    let n = std::fs::read_dir(lex.parent().unwrap()).unwrap().count();
    assert_eq!(n, 2);
    // A second build refuses: the lexicon exists.
    let snap = lex.with_file_name("snapshot.sqlite");
    assert!(build_lexicon(&snap, &schema(1), &lex).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_at_part_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: COLS.iter().map(|c| c.0.to_string()).collect(),
            },
            rows(&[("Anna", "Berg", "Aarhus")]),
        )],
    };
    let ds = dir.path().join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let target = dir.path().join("elsewhere");
    std::os::unix::fs::symlink(&target, ds.join("lexicon.sqlite.part")).unwrap();
    assert!(build_lexicon(&info.path, &schema(1), &ds.join("lexicon.sqlite")).is_err());
    assert!(!target.exists(), "the symlink was followed");
    assert!(!ds.join("lexicon.sqlite").exists());
    // The planted link is left alone (not ours to remove).
    assert!(std::fs::symlink_metadata(ds.join("lexicon.sqlite.part")).is_ok());
}
