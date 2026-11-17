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
    assert!(!checks::cpr("310490-1234")); // April has 30 days
    assert!(!checks::cpr("300290-1234")); // no Feb 30
    assert!(!checks::cpr("290291-1234")); // 1991 is not a leap year
    assert!(checks::cpr("290292-1234")); // yy % 4 == 0
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
    c.execute(
        "CREATE TABLE t (_rowid INTEGER PRIMARY KEY, status TEXT)",
        [],
    )
    .unwrap();
    for (s, n) in statuses {
        for _ in 0..*n {
            c.execute("INSERT INTO t (status) VALUES (?1)", [s])
                .unwrap();
        }
    }
    c.execute("INSERT INTO t (status) VALUES (NULL)", [])
        .unwrap();
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
    c.execute("CREATE TABLE t (_rowid INTEGER PRIMARY KEY, v TEXT)", [])
        .unwrap();
    for i in 0..1001 {
        c.execute("INSERT INTO t (v) VALUES (?1)", [format!("v{i}")])
            .unwrap();
    }
    let e = public_values(&c, "t", "v", 1).unwrap_err();
    assert!(matches!(e, ShieldError::Source { .. }));
    let s = e.to_string();
    assert!(s.contains("too many values to be a category"));
    assert!(!s.contains("v0"));
    assert_eq!(
        s,
        "snapshot, table t, column v: too many values to be a category"
    );
}

fn classify_all(
    conn: &rusqlite::Connection,
    table: &str,
    cols: &[(String, ColType)],
) -> Vec<(String, saiife_shield::classify::Guess)> {
    cols.iter()
        .map(|(c, ty)| {
            let st = stats(conn, table, c, *ty).unwrap();
            let sm = sample(conn, table, c).unwrap();
            (c.clone(), guess(c, *ty, &st, &sm))
        })
        .collect()
}

#[test]
fn danish_headers_classify() {
    let mut csv = String::from("Løn,Beløb,Født,Køn,Bemærkning,CPR-nr\n");
    for i in 0..60u32 {
        csv.push_str(&format!(
            "{}.50,{},19{:02}-01-15,{},ring op senere,0101{:02}-{:04}\n",
            20000 + i * 137,
            1000 + i * 71,
            40 + i % 50,
            if i % 2 == 0 { "M" } else { "K" },
            40 + i % 50,
            1000 + i * 3
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hr.csv"), csv).unwrap();
    let (conn, cols) = snap(dir.path(), "hr.csv");
    let names: Vec<&str> = cols.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(
        names,
        vec!["loen", "beloeb", "foedt", "koen", "bemaerkning", "cpr_nr"]
    );
    let got = classify_all(&conn, "hr", &cols);
    let class = |n: &str| got.iter().find(|g| g.0 == n).unwrap().1.class;
    assert_eq!(class("loen"), Sensitive);
    assert_eq!(class("beloeb"), Sensitive);
    assert_eq!(class("foedt"), Quasi);
    assert_eq!(class("koen"), Quasi);
    assert_eq!(class("bemaerkning"), FreeText);
    assert_eq!(class("cpr_nr"), Identifier);
}

fn big(rows: &[(String, u32)]) -> rusqlite::Connection {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute("CREATE TABLE t (_rowid INTEGER PRIMARY KEY, v TEXT)", [])
        .unwrap();
    let mut n = 0;
    for (kind, count) in rows {
        for _ in 0..*count {
            n += 1;
            let v = match kind.as_str() {
                "email" => format!("zed{n}@example.invalid"),
                "phone" => format!("+45 00 {:02} {:02} {:02}", n % 100, (n / 100) % 100, n % 97),
                other => format!("{other}{n}"),
            };
            c.execute("INSERT INTO t (v) VALUES (?1)", [v]).unwrap();
        }
    }
    c
}

fn judge(c: &rusqlite::Connection) -> (saiife_shield::classify::Guess, Option<&'static str>) {
    let st = stats(c, "t", "v", ColType::Text).unwrap();
    let sm = sample(c, "t", "v").unwrap();
    (
        guess("v", ColType::Text, &st, &sm),
        public_refusal("v", ColType::Text, &st, &sm),
    )
}

#[test]
fn mixed_identifier_column_is_not_public() {
    // 40 % emails + 45 % phones: neither check reaches 80 % alone.
    let c = big(&[
        ("email".into(), 1600),
        ("phone".into(), 1800),
        ("misc".into(), 600),
    ]);
    // True share 85 %: the draw is random, so assert the ruling only.
    let (g, r) = judge(&c);
    assert_ne!(g.class, Public);
    assert!(r.is_some());
    // 30 % + 30 %: combined 60 % is unsure, never public.
    let c = big(&[
        ("email".into(), 1200),
        ("phone".into(), 1200),
        ("misc".into(), 1600),
    ]);
    let (g, r) = judge(&c);
    assert_eq!(g.class, Sensitive);
    assert_eq!(g.reason, "some values look like identifiers");
    assert!(uncertain(&g));
    assert_eq!(r, Some("holds names or IDs"));
}

#[test]
fn sample_covers_the_whole_table() {
    // The lowest-sorted values are harmless; most rows are emails.
    let c = big(&[("aaa".into(), 400), ("email".into(), 3600)]);
    let (g, r) = judge(&c);
    assert!(matches!(g.class, Identifier | Sensitive));
    assert!(r.is_some());
}

#[test]
fn k_floor_refuses_an_identifier_value() {
    let c = mem(&[("open", 20), ("paid", 20), ("010190-1234", 15)]);
    let e = public_values(&c, "t", "status", 10).unwrap_err();
    assert_eq!(
        e.to_string(),
        "snapshot, table t, column status: a value looks like a name, ID or contact detail"
    );
    assert!(!e.to_string().contains("0101"));
}

#[test]
fn small_table_is_read_in_full() {
    // 1000 rows: 200 harmless values first, then 800 emails.
    let c = big(&[("aaa".into(), 200), ("email".into(), 800)]);
    let (g, r) = judge(&c);
    assert_eq!(g.class, Identifier);
    assert!(r.is_some());
}

#[test]
fn a_column_named_rowid_still_classifies() {
    let mut csv = String::from("RowID,Navn\n");
    for i in 0..1500 {
        csv.push_str(&format!("{},person{i}\n", 100_000 + i * 1000));
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("r.csv"), csv).unwrap();
    let (conn, cols) = snap(dir.path(), "r.csv");
    let got = classify_all(&conn, "r", &cols);
    assert_eq!(got.len(), 2);
    assert_eq!(
        got.iter().find(|g| g.0 == "navn").unwrap().1.class,
        Identifier
    );
    // The probe must see the whole table, not the user's `rowid` values.
    let sm = sample(&conn, "r", "navn").unwrap();
    assert!(sm.len() > 150);
}
