//! Plan 43 T4: the classifier, the public refusals and the k-floor.

#[path = "fixtures.rs"]
mod fixtures;

use saiife_shield::classify::{checks, guess, sample, stats, uncertain, ColumnStats};
use saiife_shield::public::{public_refusal, public_values};
use saiife_shield::schema::{ColType, ColumnClass::*};
use saiife_shield::snapshot::{build_snapshot, open_ro};
use saiife_shield::source::CsvSource;
use saiife_shield::ShieldError;

fn snap(dir: &std::path::Path, file: &str) -> (rusqlite::Connection, Vec<(String, ColType)>) {
    let f = std::fs::File::open(dir.join(file)).unwrap();
    let mut src = CsvSource::open(Box::new(f), file).unwrap();
    let out = dir.join(format!("ds-{file}"));
    let info = build_snapshot(&mut src, &out, &mut |_| {}).unwrap();
    let cols = info.tables[0]
        .3
        .iter()
        .map(|c| (c.0.clone(), c.2))
        .collect();
    (open_ro(&info.path).unwrap(), cols)
}

#[test]
fn guesses_on_fixture() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write_fixture(dir.path(), 500, 3).unwrap();
    let mut seen = std::collections::HashMap::new();
    for (file, table) in [("customers.csv", "customers"), ("invoices.csv", "invoices")] {
        let (conn, cols) = snap(dir.path(), file);
        for (c, ty) in cols {
            let st = stats(&conn, table, &c, ty).unwrap();
            let sm = sample(&conn, table, &c).unwrap();
            seen.insert(c.clone(), (guess(&c, ty, &st, &sm), ty, st, sm));
        }
    }
    for c in ["email", "phone", "ref_code", "first_name"] {
        assert_eq!(seen[c].0.class, Identifier, "{c}");
    }
    for c in ["city", "postcode", "birth_date"] {
        assert_eq!(seen[c].0.class, Quasi, "{c}");
    }
    for c in ["amount", "credit_limit"] {
        assert_eq!(seen[c].0.class, Sensitive, "{c}");
    }
    assert_eq!(seen["notes"].0.class, FreeText);
    for c in ["status", "segment"] {
        assert_eq!(seen[c].0.class, Public, "{c}");
        assert!(uncertain(&seen[c].0));
    }
    // The name word list alone is not what classifies phone and ref_code.
    let (_, ty, st, sm) = &seen["phone"];
    assert_eq!(guess("x1", *ty, st, sm).class, Identifier);
    let (_, ty, st, sm) = &seen["ref_code"];
    assert_eq!(guess("x2", *ty, st, sm).class, Identifier);
    // An unnamed column of random reals.
    let mut r = fixtures::Rng::new(9);
    let vals: Vec<String> = (0..200)
        .map(|_| format!("{}.{:03}", r.below(100_000), r.below(1000)))
        .collect();
    let st = ColumnStats {
        rows: 500,
        non_null: 500,
        distinct: 200,
        max_len: 9,
        numeric: true,
    };
    let g = guess("x9", ColType::Real, &st, &vals);
    assert_eq!(g.class, Sensitive);
    assert!(uncertain(&g));
}

#[test]
fn checks_vectors() {
    assert!(checks::iban("DE89 3704 0044 0532 0130 00"));
    assert!(checks::iban("GB82WEST12345698765432"));
    assert!(!checks::iban("DE89 3704 0044 0532 0130 01"));
    assert!(!checks::iban("hello"));
    assert!(checks::luhn("4111 1111 1111 1111"));
    assert!(!checks::luhn("4111 1111 1111 1112"));
    assert!(!checks::luhn("79927398713")); // valid Luhn but too short to be a card
    assert!(checks::cpr("010190-1234"));
    assert!(checks::cpr("0101901234"));
    assert!(!checks::cpr("320190-1234"));
    assert!(!checks::cpr("011390-1234"));
    assert!(!checks::cpr("010190-123"));
    assert!(checks::email("a.b@example.invalid"));
    assert!(!checks::email("a@b"));
    assert!(!checks::email("no at sign"));
    assert!(checks::phone("12345678"));
    assert!(checks::phone("+45 00 12 34 56"));
    assert!(!checks::phone("12"));
    assert!(checks::amount_name("credit_limit"));
    assert!(!checks::amount_name("status"));
}

#[test]
fn public_refused_for_identifiers_and_amounts() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write_fixture(dir.path(), 500, 3).unwrap();
    let (conn, cols) = snap(dir.path(), "customers.csv");
    let check = |c: &str| {
        let ty = cols.iter().find(|x| x.0 == c).unwrap().1;
        let st = stats(&conn, "customers", c, ty).unwrap();
        let sm = sample(&conn, "customers", c).unwrap();
        public_refusal(c, ty, &st, &sm)
    };
    assert_eq!(check("email"), Some("holds names or IDs"));
    assert_eq!(check("credit_limit"), Some("holds amounts"));
    assert_eq!(check("id"), Some("holds names or IDs"));
    assert_eq!(check("segment"), None);
    // No k-floor list is computed for a refused column.
    assert!(public_values(&conn, "customers", "email", 1).is_err());
    assert!(public_values(&conn, "customers", "credit_limit", 1).is_err());
}

fn mem(statuses: &[(&str, u32)]) -> rusqlite::Connection {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute("CREATE TABLE t (status TEXT)", []).unwrap();
    for (s, n) in statuses {
        for _ in 0..*n {
            c.execute("INSERT INTO t VALUES (?1)", [s]).unwrap();
        }
    }
    c.execute("INSERT INTO t VALUES (NULL)", []).unwrap();
    c
}

#[test]
fn k_floor_counts() {
    let c = mem(&[("open", 12), ("paid", 30), ("disputed", 3)]);
    let pv = public_values(&c, "t", "status", 10).unwrap();
    assert_eq!(pv.column, "status");
    assert_eq!(pv.passing, vec!["open", "paid"]);
    assert_eq!(pv.total_distinct, 3);
}

#[test]
fn too_many_values_refused() {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute("CREATE TABLE t (v TEXT)", []).unwrap();
    for i in 0..1001 {
        c.execute("INSERT INTO t VALUES (?1)", [format!("v{i}")])
            .unwrap();
    }
    let e = public_values(&c, "t", "v", 1).unwrap_err();
    assert!(matches!(e, ShieldError::Source { .. }));
    let s = e.to_string();
    assert!(s.contains("too many values to be a category"));
    assert!(!s.contains("v0"));
}
