//! Plan 45 Task 3: the executor, caps, list cap, existence check (R45-6,
//! R45-7) and self-checks.

mod common;

use common::*;
use saiife_shield::calc::{run, CalcFailure, Caps, CellValue};
use saiife_shield::plan::SelfCheck;
use saiife_shield::schema::{Bound, Decimal, Param, ParamType};
use saiife_shield::sql::validate;
use saiife_shield::sql::{validate_check, ErrorClass, ValidatedCheck};

const BALANCE: &str = "SELECT SUM(i.amount) AS owed, c.credit_limit FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'";
const J: &str = "FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";

fn caps() -> Caps {
    Caps::default()
}

fn fail(r: Result<saiife_shield::calc::ResultSet, CalcFailure>) -> CalcFailure {
    match r {
        Ok(rs) => panic!("expected a refusal, got {rs:?}"),
        Err(f) => f,
    }
}

#[test]
fn runs_balance() {
    let mut db = fixture();
    let ps = vec![entity(1)];
    let val = v(BALANCE, &ps);
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.columns.len(), 2);
    assert_eq!(rs.rows.len(), 1);
    let expect: f64 = {
        let mut st = db
            .prepare("SELECT amount FROM invoices WHERE customer_id = 1 AND status = 'open'")
            .unwrap();
        st.query_map([], |r| r.get::<_, f64>(0))
            .unwrap()
            .map(|x| x.unwrap())
            .sum()
    };
    assert_eq!(rs.rows[0][0], CellValue::Real(expect));
    assert_eq!(rs.rows[0][0], CellValue::Real(600.0));
    assert_eq!(rs.rows[0][1], CellValue::Real(5000.0));
    assert!(!rs.truncated);
    assert_eq!(rs.total_rows, None);
    assert_eq!(rs.row_band, "<100");
}

#[test]
fn list_cap_and_total() {
    let mut db = fixture();
    let ps = vec![entity(7)];
    let val = v(&format!("SELECT i.id, i.amount {J}"), &ps);
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows.len(), 100);
    assert!(rs.truncated);
    assert_eq!(rs.total_rows, Some(250));
    assert_eq!(rs.row_band, saiife_shield::schema::rows_band(250));
    // A small list is not truncated.
    let ps = vec![entity(1)];
    let val = v(&format!("SELECT i.id, i.amount {J}"), &ps);
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows.len(), 4);
    assert!(!rs.truncated);
}

#[test]
fn empty_sum_for_key_refuses() {
    let mut db = fixture();
    // customer 3 exists but has no invoices; a key that is not there at all.
    for key in [3, 999] {
        let ps = vec![entity(key)];
        let f = fail(run(&mut db, &v(BALANCE, &ps), &[], &ps, &caps()));
        assert_eq!(
            f,
            CalcFailure {
                class: ErrorClass::CheckFailed,
                empty_for: Some("p1".into())
            }
        );
    }
}

#[test]
fn existence_check_refuses_crafted_method() {
    let mut db = fixture();
    let ps = vec![entity(3)];
    // Refused by the existence check (check_failed + empty_for), not by the
    // empty-result rule (empty_result): the method never ran.
    let f = fail(run(&mut db, &v(BALANCE, &ps), &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::CheckFailed);
    assert_eq!(f.empty_for.as_deref(), Some("p1"));
    // The same shape as a COUNT-only method is a computed 0.
    let val = v(&format!("SELECT COUNT(*) AS n {J}"), &ps);
    assert!(val.count_only);
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows, vec![vec![CellValue::Int(0)]]);
}

#[test]
fn count_zero_allowed() {
    let mut db = fixture();
    let ps = vec![entity(1)];
    // Existing key with linked rows, but a filter that matches none: COUNT 0.
    let val = v(
        &format!("SELECT COUNT(*) AS n {J} AND i.issued > '2030-01-01'"),
        &ps,
    );
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows, vec![vec![CellValue::Int(0)]]);
    // An absent key still refuses even for a COUNT.
    let ps = vec![entity(999)];
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::CheckFailed);
    assert_eq!(f.empty_for.as_deref(), Some("p1"));
}

#[test]
fn empty_result_is_distinct_from_empty_for_key() {
    let mut db = fixture();
    let ps = vec![entity(1)];
    // The key and its invoices exist, but the pinned HAVING filters all.
    let val = v(
        &format!("SELECT SUM(i.amount) AS s {J} HAVING COUNT(*) > 100"),
        &ps,
    );
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::EmptyResult);
    assert_eq!(f.empty_for.as_deref(), Some("p1"));
    // All-NULL nullable aggregate: no row matches the status filter.
    let val = v(
        &format!("SELECT SUM(i.amount) AS s {J} AND i.issued > '2030-01-01'"),
        &ps,
    );
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::EmptyResult);
    // Without an entity param zero rows is a normal empty result.
    let val = v("SELECT i.status, COUNT(*) AS n FROM invoices i WHERE i.issued > '2030-01-01' GROUP BY i.status", &[]);
    let rs = run(&mut db, &val, &[], &[], &caps()).unwrap();
    assert!(rs.rows.is_empty());
}

#[test]
fn param_bound_to_two_keys_is_runtime_error() {
    let mut db = fixture();
    let val = v(BALANCE, &[entity(1)]);
    let mut p = entity(1);
    p.bound = Some(Bound::Keys(vec![1, 2]));
    let ps = vec![p];
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::RuntimeError);
    assert_eq!(f.empty_for, None);
    // Unbound is the same.
    let mut p = entity(1);
    p.bound = None;
    let ps = vec![p];
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::RuntimeError);
}

#[test]
fn binds_param_kinds() {
    let mut db = fixture();
    let amount = Param {
        name: "p2".into(),
        ty: ParamType::Amount,
        bound: Some(Bound::Amount(Decimal::parse_plain("150.50").unwrap())),
        display: "150.50".into(),
    };
    let ps = vec![entity(1), amount];
    let val = v(&format!("SELECT COUNT(*) AS n {J} AND i.amount > :p2"), &ps);
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows, vec![vec![CellValue::Int(2)]]);
    let range = Param {
        name: "p3".into(),
        ty: ParamType::DateRange,
        bound: Some(Bound::DateRange("2026-02-01".into(), "2026-03-06".into())),
        display: "range".into(),
    };
    let ps = vec![entity(1), range];
    let val = v(
        &format!("SELECT COUNT(*) AS n {J} AND i.issued >= :p3_from AND i.issued < :p3_to"),
        &ps,
    );
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    assert_eq!(rs.rows, vec![vec![CellValue::Int(2)]]);
}

fn big() -> rusqlite::Connection {
    let db = fixture();
    heavy(&db, 200_000);
    db
}

const HEAVY: &str = "SELECT i.customer_id, SUM(i.amount) AS s FROM invoices i \
    GROUP BY i.customer_id ORDER BY s DESC";

#[test]
fn time_cap() {
    let mut db = big();
    let val = v(HEAVY, &[]);
    let c = Caps {
        wall_ms: 1,
        ..Caps::default()
    };
    let f = fail(run(&mut db, &val, &[], &[], &c));
    assert_eq!(f.class, ErrorClass::TimeCap);
    assert_eq!(f.empty_for, None);
}

#[test]
fn step_cap() {
    let mut db = big();
    let val = v(HEAVY, &[]);
    let c = Caps {
        steps: 1000,
        ..Caps::default()
    };
    let f = fail(run(&mut db, &val, &[], &[], &c));
    assert_eq!(f.class, ErrorClass::StepCap);
    // The connection is usable again afterwards with sane caps.
    let rs = run(&mut db, &val, &[], &[], &caps()).unwrap();
    assert!(rs.truncated);
}

#[test]
fn checks_run() {
    let mut db = fixture();
    let ps = vec![entity(1)];
    let val = v(
        &format!("SELECT i.id, i.amount {J} AND i.status = 'open'"),
        &ps,
    );
    let sch = schema();
    let rows = |min, max| {
        validate_check(&SelfCheck::RowsBetween { min, max }, &sch, &public(), &ps).unwrap()
    };
    // 3 open invoices: 1..=1 fails, 3..=3 passes.
    let f = fail(run(&mut db, &val, &[rows(1, 1)], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::CheckFailed);
    assert_eq!(f.empty_for, None);
    run(&mut db, &val, &[rows(3, 3)], &ps, &caps()).unwrap();
    // Equal over two scalar sums.
    let eq = |a: &str, b: &str| -> ValidatedCheck {
        validate_check(
            &SelfCheck::Equal {
                a: a.into(),
                b: b.into(),
            },
            &sch,
            &public(),
            &ps,
        )
        .unwrap()
    };
    let a = format!("SELECT SUM(i.amount) AS s {J} AND i.status = 'open'");
    let same = format!("SELECT SUM(i.amount) AS t {J} AND i.status = 'open'");
    run(&mut db, &val, &[eq(&a, &same)], &ps, &caps()).unwrap();
    let other = format!("SELECT SUM(i.amount) AS t {J} AND i.status = 'paid'");
    let f = fail(run(&mut db, &val, &[eq(&a, &other)], &ps, &caps()));
    assert_eq!(f.class, ErrorClass::CheckFailed);
}

#[test]
fn read_only() {
    let dir = std::env::temp_dir().join(format!("p45-t3-ro-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("snap.db");
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(DDL).unwrap();
        db.execute_batch("INSERT INTO invoices VALUES (1,1,5,'open','2026-01-01',0);")
            .unwrap();
    }
    let mut ro = saiife_shield::snapshot::open_ro(&path).unwrap();
    let val = v(HEAVY, &[]);
    run(&mut ro, &val, &[], &[], &caps()).unwrap();
    assert!(ro.execute_batch("CREATE TABLE x(a)").is_err());
    assert!(ro
        .execute_batch("INSERT INTO invoices VALUES (9,1,5,'open','2026-01-01',0)")
        .is_err());
    // query_only also guards a writable connection after the executor ran.
    let mut rw = fixture();
    run(&mut rw, &val, &[], &[], &caps()).unwrap();
    assert!(rw.execute_batch("CREATE TABLE x(a)").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serde_round_trip() {
    let f = CalcFailure {
        class: ErrorClass::EmptyResult,
        empty_for: Some("p1".into()),
    };
    let j = serde_json::to_string(&f).unwrap();
    assert_eq!(serde_json::from_str::<CalcFailure>(&j).unwrap(), f);
    let c = Caps::default();
    assert_eq!(
        (c.wall_ms, c.steps, c.heap_bytes, c.list_cap),
        (10_000, 2_000_000_000, 512 * 1024 * 1024, 100)
    );
    let cell = vec![
        CellValue::Null,
        CellValue::Int(1),
        CellValue::Real(1.5),
        CellValue::Text("a".into()),
    ];
    let j = serde_json::to_string(&cell).unwrap();
    assert_eq!(serde_json::from_str::<Vec<CellValue>>(&j).unwrap(), cell);
}

#[test]
fn placeholders_bind_by_exact_name() {
    let mut db = fixture();
    // The method uses only `:p10`; the executor's list also holds `p1`.
    let sql = "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p10";
    let draft = vec![entity_named("p10", 2)];
    let val = v(sql, &draft);
    let ps = vec![entity_named("p1", 1), entity_named("p10", 2)];
    let rs = run(&mut db, &val, &[], &ps, &caps()).unwrap();
    // Customer 2 has one invoice, customer 1 four: it bound p10, not p1.
    assert_eq!(rs.rows, vec![vec![CellValue::Int(1)]]);
    // The existence check is on p10's key: an absent p10 refuses with p10
    // named, whatever p1 holds.
    let ps = vec![entity_named("p1", 1), entity_named("p10", 999)];
    let f = fail(run(&mut db, &val, &[], &ps, &caps()));
    assert_eq!(f.empty_for.as_deref(), Some("p10"));
    // `:p1x` and an unknown placeholder never bind; `:p1_to` on a non-range
    // parameter neither (executor).
    for bad in [":p1x", ":p9", ":p1_to", ":p1_from", ":zz"] {
        let sql = format!("SELECT COUNT(*) AS n FROM invoices i WHERE i.customer_id = {bad}");
        let mut val = v("SELECT COUNT(*) AS n FROM invoices i", &[]);
        val.sql = sql;
        let ps = vec![entity_named("p1", 1)];
        let f = fail(run(&mut db, &val, &[], &ps, &caps()));
        assert_eq!(f.class, ErrorClass::RuntimeError, "{bad}");
    }
}

#[test]
fn validator_refuses_inexact_placeholders() {
    let ps = vec![entity_named("p1", 1), entity_named("p10", 2)];
    for bad in [":p1x", ":p9", ":p1_to", ":p1_from", ":p10_to"] {
        let sql = format!(
            "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.customer_id \
             WHERE c.id = :p1 AND c.id = {bad}"
        );
        assert!(validate(&sql, &schema(), &public(), &ps).is_err(), "{bad}");
    }
    // A bound entity param the method does not use is refused.
    let sql = "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p10";
    assert!(validate(sql, &schema(), &public(), &ps).is_err());
    // More than ten params resolve exactly.
    let many: Vec<Param> = (1..=12)
        .map(|n| entity_named(&format!("p{n}"), n))
        .collect();
    let sql = "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p12";
    let only = vec![many[11].clone()];
    assert!(validate(sql, &schema(), &public(), &only).is_ok());
}

#[test]
fn equal_is_strict() {
    let mut db = fixture();
    let sch = schema();
    let mut eqchk = |key: i64| {
        let ps = vec![entity(key)];
        let a = format!("SELECT SUM(i.amount) AS s {J} AND i.status = 'open'");
        let b = format!("SELECT SUM(i.amount) AS t {J} AND i.status = 'paid'");
        let c = validate_check(&SelfCheck::Equal { a, b }, &sch, &public(), &ps).unwrap();
        let val = v(&format!("SELECT COUNT(*) AS n {J}"), &ps);
        run(&mut db, &val, &[c], &ps, &caps())
    };
    // A real cent at 1e7 is a difference.
    assert_eq!(fail(eqchk(8)).class, ErrorClass::CheckFailed);
    // 0.1 + 0.2 equals 0.3.
    eqchk(9).unwrap();
}

#[test]
fn zero_caps_refused() {
    let mut db = fixture();
    let val = v(HEAVY, &[]);
    for c in [
        Caps {
            list_cap: 0,
            ..Caps::default()
        },
        Caps {
            wall_ms: 0,
            ..Caps::default()
        },
        Caps {
            steps: 0,
            ..Caps::default()
        },
        Caps {
            heap_bytes: 0,
            ..Caps::default()
        },
        Caps {
            heap_bytes: -5,
            ..Caps::default()
        },
    ] {
        assert_eq!(
            fail(run(&mut db, &val, &[], &[], &c)).class,
            ErrorClass::RuntimeError
        );
    }
}

#[test]
fn computed_outputs_need_an_alias() {
    for sql in [
        "SELECT SUM(i.amount) FROM invoices i",
        "SELECT i.status, COUNT(*) FROM invoices i GROUP BY i.status",
    ] {
        let e = validate(sql, &schema(), &public(), &[]).unwrap_err();
        assert_eq!(e.class, ErrorClass::ConstructNotAllowed, "{sql}");
    }
    assert!(validate(
        "SELECT SUM(i.amount) AS s FROM invoices i",
        &schema(),
        &public(),
        &[]
    )
    .is_ok());
}
