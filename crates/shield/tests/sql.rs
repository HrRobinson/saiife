//! Plan 45 Task 1: the planner reply types and the SELECT-only SQL subset
//! validator (R45-1..R45-5, R45-8).

use saiife_shield::plan::{parse_reply, SelfCheck, PLAN_SCHEMA};
use saiife_shield::public::PublicValues;
use saiife_shield::schema::{
    Bound, ColType, ColumnClass, ColumnInfo, EntitySpec, Param, ParamType, Schema, TableInfo,
};
use saiife_shield::sql::{validate, validate_check, ErrorClass, MethodError, ValidatedCheck};

fn col(name: &str, ty: ColType, class: ColumnClass) -> ColumnInfo {
    ColumnInfo {
        name: name.into(),
        ty,
        class,
        alias: None,
    }
}

/// customers(id, first_name, last_name, city, credit_limit, segment),
/// invoices(id, customer_id, amount, status, issued).
fn schema() -> Schema {
    use ColType::*;
    use ColumnClass::*;
    Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![
            TableInfo {
                name: "customers".into(),
                alias: None,
                rows: 500,
                columns: vec![
                    col("id", Integer, Identifier),
                    col("first_name", Text, Identifier),
                    col("last_name", Text, Identifier),
                    col("city", Text, Quasi),
                    col("credit_limit", Real, Sensitive),
                    col("segment", Text, Public),
                ],
            },
            TableInfo {
                name: "invoices".into(),
                alias: None,
                rows: 5000,
                columns: vec![
                    col("id", Integer, Identifier),
                    col("customer_id", Integer, Identifier),
                    col("amount", Real, Sensitive),
                    col("status", Text, Public),
                    col("issued", Date, Quasi),
                ],
            },
        ],
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

fn aliased_schema() -> Schema {
    let mut s = schema();
    s.tables[0].alias = Some("clients".into());
    s.tables[0].columns[3].alias = Some("town".into());
    s
}

fn public() -> Vec<PublicValues> {
    vec![PublicValues {
        column: "invoices.status".into(),
        passing: vec!["open".into(), "paid".into()],
        total_distinct: 3,
    }]
}

fn entity(name: &str) -> Param {
    Param {
        name: name.into(),
        ty: ParamType::Entity {
            table: "customers".into(),
            word: "customer".into(),
        },
        bound: Some(Bound::Keys(vec![4411])),
        display: "Anna Berg (customer #4411)".into(),
    }
}

fn plain(name: &str, ty: ParamType) -> Param {
    Param {
        name: name.into(),
        ty,
        bound: None,
        display: String::new(),
    }
}

fn params() -> Vec<Param> {
    vec![
        entity("p1"),
        plain("p2", ParamType::Amount),
        plain("p3", ParamType::DateRange),
        plain(
            "p4",
            ParamType::Text {
                table: "customers".into(),
                column: "city".into(),
            },
        ),
        plain("p5", ParamType::Date),
    ]
}

fn ok(sql: &str) -> saiife_shield::sql::Validated {
    match validate(sql, &schema(), &public(), &params()) {
        Ok(v) => v,
        Err(e) => panic!("{sql}: refused {e:?}"),
    }
}

fn class_of(sql: &str, schema: &Schema, params: &[Param]) -> ErrorClass {
    match validate(sql, schema, &public(), params) {
        Ok(v) => panic!("{sql}: accepted as {}", v.sql),
        Err(e) => e.class,
    }
}

fn refused(sql: &str) -> ErrorClass {
    class_of(sql, &schema(), &params())
}

/// The rendered SQL must prepare against a real SQLite database holding the
/// snapshot names.
fn prepares(sql: &str) {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE customers(id INTEGER, first_name TEXT, last_name TEXT, city TEXT, \
         credit_limit REAL, segment TEXT);\
         CREATE TABLE invoices(id INTEGER, customer_id INTEGER, amount REAL, status TEXT, \
         issued TEXT);",
    )
    .unwrap();
    let r = db.prepare(sql).map(|_| ());
    if let Err(e) = r {
        panic!("{sql}: does not prepare: {e}");
    }
}

const BALANCE: &str = "SELECT SUM(i.amount) AS owed, c.credit_limit FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'";

#[test]
fn accepts_balance_method() {
    let v = ok(BALANCE);
    assert_eq!(v.cloud_sql, BALANCE);
    assert_eq!(v.params_used, vec!["p1".to_string()]);
    assert_eq!(v.entity_params, vec!["p1".to_string()]);
    assert_eq!(v.aggregates_nullable, vec![0]);
    assert_eq!(v.sql, v.ast.to_string());
    assert!(v.sql.contains(":p1"), "{}", v.sql);
    assert!(v.sql.contains("'open'"), "{}", v.sql);
    prepares(&v.sql);

    // COUNT is not a nullable aggregate; a pass-through derived SUM is.
    let v = ok(
        "SELECT COUNT(*) AS n, MAX(i.amount) AS top FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
    );
    assert_eq!(v.aggregates_nullable, vec![1]);
    let v = ok(
        "SELECT t.owed FROM (SELECT SUM(i.amount) AS owed FROM invoices i \
         WHERE i.status = 'paid') t",
    );
    assert_eq!(v.aggregates_nullable, vec![0]);
    prepares(&v.sql);
}

#[test]
fn wide_method_renders_and_prepares() {
    let sql = "WITH big AS (SELECT i.customer_id AS cid, SUM(i.amount) AS total \
         FROM invoices i WHERE i.issued >= :p3_from AND i.issued < :p3_to \
         GROUP BY i.customer_id HAVING SUM(i.amount) > :p2) \
         SELECT c.city, COUNT(*) AS n, ROUND(AVG(b.total), 2) AS avg_total, \
         CAST(MAX(b.total) AS INTEGER) AS top, \
         CASE WHEN COUNT(*) > 3 THEN 1 ELSE 0 END AS flag \
         FROM big b LEFT JOIN customers c ON c.id = b.cid \
         WHERE c.city = :p4 AND EXISTS (SELECT 1 FROM invoices j WHERE j.customer_id = c.id \
         AND j.status IN ('open', 'paid')) \
         AND c.id IN (SELECT k.customer_id FROM invoices k WHERE k.issued < '2026-01-01' \
         AND strftime('%Y-%m', k.issued) = strftime('%Y-%m', date('now', '-1 month'))) \
         GROUP BY c.city ORDER BY n DESC LIMIT 10 OFFSET 5";
    let v = ok(sql);
    assert_eq!(v.params_used, vec!["p3", "p2", "p4"]);
    assert!(v.entity_params.is_empty());
    assert_eq!(v.aggregates_nullable, vec![2, 3]);
    prepares(&v.sql);
}

#[test]
fn aliases_map_back() {
    let s = aliased_schema();
    let v = validate(
        "SELECT c.town, COUNT(*) AS n FROM clients c GROUP BY c.town",
        &s,
        &public(),
        &params(),
    )
    .unwrap();
    assert!(v.sql.contains("customers"), "{}", v.sql);
    assert!(v.sql.contains("\"city\""), "{}", v.sql);
    assert!(!v.sql.contains("clients c"), "{}", v.sql);
    prepares(&v.sql);
    // Unqualified, the table name stays the reference name.
    let v = validate(
        "SELECT clients.town FROM clients WHERE clients.id = :p1",
        &s,
        &public(),
        &params(),
    )
    .unwrap();
    assert!(v.sql.contains("customers"), "{}", v.sql);
    assert_eq!(v.entity_params, vec!["p1"]);
    prepares(&v.sql);
    // The output column keeps the cloud name the planner wrote.
    let v = validate("SELECT town FROM clients", &s, &public(), &params()).unwrap();
    assert!(v.sql.contains("AS \"town\""), "{}", v.sql);
    prepares(&v.sql);
    // The snapshot names are not the cloud's names.
    assert_eq!(
        class_of("SELECT c.city FROM clients c", &s, &params()),
        ErrorClass::UnknownColumn
    );
    let e = validate("SELECT id FROM customers", &s, &public(), &params()).unwrap_err();
    assert_eq!(e.class, ErrorClass::UnknownTable);
    assert_eq!(e.detail.as_deref(), Some("customers"));
}

#[test]
fn refuses_by_class() {
    use ErrorClass::*;
    let five_joins = "SELECT c.id FROM customers c JOIN invoices a ON a.customer_id = c.id \
        JOIN invoices b ON b.customer_id = c.id JOIN invoices d ON d.customer_id = c.id \
        JOIN invoices e ON e.customer_id = c.id JOIN invoices f ON f.customer_id = c.id";
    let four_joins = "SELECT c.id FROM customers c JOIN invoices a ON a.customer_id = c.id \
        JOIN invoices b ON b.customer_id = c.id JOIN invoices d ON d.customer_id = c.id \
        JOIN invoices e ON e.customer_id = c.id";
    ok(four_joins);
    let depth2 = "SELECT c.id FROM customers c WHERE c.id IN (SELECT a.customer_id FROM \
        invoices a WHERE a.id IN (SELECT b.id FROM invoices b))";
    ok(depth2);
    let depth3 = "SELECT c.id FROM customers c WHERE c.id IN (SELECT a.customer_id FROM \
        invoices a WHERE a.id IN (SELECT b.id FROM invoices b WHERE b.id IN \
        (SELECT d.id FROM invoices d)))";
    let wide: Vec<String> = (0..33).map(|i| format!("c.id AS x{i}")).collect();
    let wide = format!("SELECT {} FROM customers c", wide.join(", "));
    let cases: Vec<(&str, ErrorClass)> = vec![
        ("PRAGMA x", NotSelect),
        ("ATTACH DATABASE 'x.db' AS x", NotSelect),
        ("DELETE FROM customers", NotSelect),
        (
            "SELECT c.id FROM customers c; SELECT c.id FROM customers c",
            MultipleStatements,
        ),
        ("SELEC id FROM customers", Syntax),
        ("", Syntax),
        ("SELECT * FROM sqlite_master", UnknownTable),
        ("SELECT load_extension('x')", FunctionNotAllowed),
        ("SELECT random() AS r FROM customers c", FunctionNotAllowed),
        (
            "SELECT SUM(i.amount) OVER () AS s FROM invoices i",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id FROM customers c UNION SELECT i.id FROM invoices i",
            ConstructNotAllowed,
        ),
        ("SELECT * FROM customers", ConstructNotAllowed),
        ("SELECT c.* FROM customers c", ConstructNotAllowed),
        (
            "SELECT c.id FROM customers c, invoices i",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id FROM customers c CROSS JOIN invoices i",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id FROM customers c LIMIT :p2",
            ConstructNotAllowed,
        ),
        (
            "SELECT (SELECT 1) AS x FROM customers c",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id FROM customers c WHERE c.city LIKE 'A%'",
            ConstructNotAllowed,
        ),
        (
            "WITH RECURSIVE r AS (SELECT 1 AS n) SELECT r.n FROM r",
            ConstructNotAllowed,
        ),
        (
            "SELECT CAST(c.id AS BLOB) AS b FROM customers c",
            ConstructNotAllowed,
        ),
        (five_joins, TooManyJoins),
        (depth3, TooDeep),
        (&wide, TooManyColumns),
        (
            "SELECT i.id FROM invoices i WHERE i.status = 'disputed'",
            LiteralNotAllowed,
        ),
        (
            "SELECT c.id FROM customers c WHERE c.last_name = 'Berg'",
            LiteralNotAllowed,
        ),
        ("SELECT 'Berg' AS n FROM customers c", LiteralNotAllowed),
        (
            "SELECT c.id FROM customers c WHERE c.first_name = :p1",
            ParamMisuse,
        ),
        ("SELECT c.id FROM customers c WHERE c.id = :p9", ParamMisuse),
        ("SELECT c.id FROM customers c WHERE c.id > :p1", ParamMisuse),
        ("SELECT :p2 AS x FROM customers c", ParamMisuse),
        ("SELECT c.id FROM customers c WHERE c.id = ?", ParamMisuse),
        (
            "SELECT i.id FROM invoices i WHERE i.issued >= :p2",
            ErrorClass::ParamType,
        ),
        (
            "SELECT i.id FROM invoices i WHERE i.amount > :p5",
            ErrorClass::ParamType,
        ),
        (
            "SELECT c.id FROM customers c WHERE c.segment = :p4",
            ErrorClass::ParamType,
        ),
    ];
    for (sql, want) in cases {
        assert_eq!(refused(sql), want, "{sql}");
    }
    // A key with two candidates is not a stage-1 pick.
    let mut ps = params();
    ps[0].bound = Some(Bound::Keys(vec![1, 2]));
    assert_eq!(
        class_of(
            "SELECT c.city FROM customers c WHERE c.id = :p1",
            &schema(),
            &ps
        ),
        ErrorClass::ParamMisuse
    );
    // IN (:pN) on the key is the other allowed form.
    let v = ok("SELECT c.city FROM customers c WHERE c.id IN (:p1)");
    assert_eq!(v.entity_params, vec!["p1"]);
    let v = ok("SELECT c.city FROM customers c WHERE :p1 = c.id");
    assert_eq!(v.entity_params, vec!["p1"]);
}

#[test]
fn null_masking_refused() {
    let masks = [
        "SELECT COALESCE(SUM(i.amount), 0) AS owed FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT TOTAL(i.amount) AS owed FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT IFNULL(MAX(i.amount), 0) AS top FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT NULLIF(SUM(i.amount), 0) AS owed FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT CASE WHEN SUM(i.amount) IS NULL THEN 0 ELSE SUM(i.amount) END AS owed \
         FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT COALESCE(t.owed, 0) AS owed FROM (SELECT SUM(i.amount) AS owed \
         FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1) t",
    ];
    for sql in masks {
        assert_eq!(refused(sql), ErrorClass::NullMasking, "{sql}");
    }
    // An entity param that is bound but not in the query still counts.
    assert_eq!(
        refused("SELECT TOTAL(i.amount) AS s FROM invoices i"),
        ErrorClass::NullMasking
    );
    // The same without an entity param is fine.
    let no_entity: Vec<Param> = params().into_iter().skip(1).collect();
    for sql in [
        "SELECT COALESCE(SUM(i.amount), 0) AS s FROM invoices i WHERE i.status = 'open'",
        "SELECT TOTAL(i.amount) AS s FROM invoices i",
        "SELECT IFNULL(MAX(i.amount), 0) AS top FROM invoices i",
    ] {
        if let Err(e) = validate(sql, &schema(), &public(), &no_entity) {
            panic!("{sql}: {e:?}");
        }
    }
    // COALESCE of a plain column with the key bound is not masking an empty result.
    ok(
        "SELECT SUM(COALESCE(i.amount, 0)) AS owed FROM invoices i JOIN customers c \
        ON c.id = i.customer_id WHERE c.id = :p1",
    );
}

#[test]
fn escape_attempts_refused() {
    use ErrorClass::*;
    let s = schema();
    let ps = params();
    let cases: Vec<(&str, ErrorClass)> = vec![
        ("SELECT m.name FROM sqlite_master m", UnknownTable),
        ("SELECT m.sql FROM sqlite_schema m", UnknownTable),
        ("SELECT c.id FROM main.customers c", UnknownTable),
        ("SELECT c.id FROM temp.customers c", UnknownTable),
        (
            "SELECT p.name FROM pragma_table_info('customers') p",
            ConstructNotAllowed,
        ),
        // A CTE shadowing a real table (any case) is refused.
        (
            "WITH customers AS (SELECT i.amount AS id FROM invoices i) \
             SELECT c.id FROM customers c",
            ConstructNotAllowed,
        ),
        (
            "WITH Invoices AS (SELECT c.id AS id FROM customers c) \
             SELECT x.id FROM Invoices x",
            ConstructNotAllowed,
        ),
        // A quoted identifier that is not a schema name (SQLite would read it as text).
        ("SELECT \"Berg\" AS n FROM customers c", UnknownColumn),
        ("SELECT c.id FROM \"Customers\" c", UnknownTable),
        ("SELECT c.id FROM \"customers \" c", UnknownTable),
        // An alias used with a column not in that table.
        ("SELECT c.email FROM customers AS c", UnknownColumn),
        ("SELECT c.amount FROM customers AS c", UnknownColumn),
        ("SELECT c.rowid FROM customers AS c", UnknownColumn),
        ("SELECT x.id FROM customers AS c", UnknownTable),
        // Another case.
        ("SELECT c.City FROM customers c", UnknownColumn),
        ("SELECT c.id FROM Customers c", UnknownTable),
        ("SELECT C.id FROM customers c", UnknownTable),
        (
            "SELECT COUNT(*) AS n FROM customers c ORDER BY N",
            UnknownColumn,
        ),
        // Ambiguous bare names and colliding reference names.
        (
            "SELECT id FROM customers c JOIN invoices i ON i.customer_id = c.id",
            UnknownColumn,
        ),
        (
            "SELECT c.id FROM customers c JOIN invoices C ON C.customer_id = c.id",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id FROM invoices AS customers JOIN customers c ON 1 = 1",
            ConstructNotAllowed,
        ),
        ("SELECT load_extension('/x.so') AS x", FunctionNotAllowed),
        ("SELECT c.id FROM customers c WHERE c.id = @p1", ParamMisuse),
        ("SELECT c.id FROM customers c WHERE c.id = $p1", ParamMisuse),
        ("SELECT c.id FROM customers c WHERE c.id = :P1", ParamMisuse),
        (
            "SELECT c.id COLLATE nocase AS x FROM customers c",
            ConstructNotAllowed,
        ),
    ];
    for (sql, want) in cases {
        assert_eq!(class_of(sql, &s, &ps), want, "{sql}");
    }
    // A quoted schema name is still the schema name.
    let v = ok("SELECT \"c\".\"city\" FROM \"customers\" \"c\"");
    prepares(&v.sql);
    // The CTE-shadow rule holds against the snapshot name behind an alias too.
    let a = aliased_schema();
    assert_eq!(
        class_of(
            "WITH customers AS (SELECT i.id AS id FROM invoices i) \
             SELECT x.id FROM customers x",
            &a,
            &ps
        ),
        ConstructNotAllowed
    );
    // Error details carry only the cloud name, capped.
    let long = "x".repeat(300);
    let e = validate(&format!("SELECT c.id FROM {long} c"), &s, &public(), &ps).unwrap_err();
    assert_eq!(e.class, UnknownTable);
    assert!(e.detail.as_ref().unwrap().chars().count() <= 120);
    let e = validate("SELEC 'Anna Berg'", &s, &public(), &ps).unwrap_err();
    assert_eq!(
        e,
        MethodError {
            class: Syntax,
            detail: None
        }
    );
    let e = validate(
        "SELECT c.id FROM customers c WHERE c.last_name = 'Berg'",
        &s,
        &public(),
        &ps,
    )
    .unwrap_err();
    assert_eq!(e.detail, None);
}

#[test]
fn date_range_params() {
    let v =
        ok("SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3_from AND i.issued < :p3_to");
    assert_eq!(v.params_used, vec!["p3"]);
    assert!(
        v.sql.contains(":p3_from") && v.sql.contains(":p3_to"),
        "{}",
        v.sql
    );
    prepares(&v.sql);
    ok("SELECT COUNT(*) AS n FROM invoices i WHERE :p3_from <= i.issued AND :p3_to > i.issued");
    ok("SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p5");
    use ErrorClass::*;
    for (sql, want) in [
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3",
            ParamMisuse,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued <= :p3_to",
            ParamMisuse,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued < :p3_from",
            ParamMisuse,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.amount >= :p3_from",
            ErrorClass::ParamType,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p5_from",
            ParamMisuse,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3_until",
            ParamMisuse,
        ),
    ] {
        assert_eq!(refused(sql), want, "{sql}");
    }
}

#[test]
fn checks_validate() {
    let s = schema();
    let ps = params();
    let c = SelfCheck::Equal {
        a: "SELECT COUNT(*) AS n FROM invoices i".into(),
        b: "SELECT COUNT(i.id) AS n FROM invoices i".into(),
    };
    match validate_check(&c, &s, &public(), &ps).unwrap() {
        ValidatedCheck::Equal { a, b } => {
            assert!(a.sql.contains("COUNT"));
            assert!(b.sql.contains("COUNT"));
        }
        other => panic!("{other:?}"),
    }
    let r = SelfCheck::RowsBetween { min: 1, max: 1 };
    assert_eq!(
        validate_check(&r, &s, &public(), &ps).unwrap(),
        ValidatedCheck::RowsBetween { min: 1, max: 1 }
    );
    let bad = SelfCheck::RowsBetween { min: 2, max: 1 };
    assert!(validate_check(&bad, &s, &public(), &ps).is_err());
    let two = SelfCheck::Equal {
        a: "SELECT COUNT(*) AS n, MAX(i.id) AS m FROM invoices i".into(),
        b: "SELECT COUNT(*) AS n FROM invoices i".into(),
    };
    assert_eq!(
        validate_check(&two, &s, &public(), &ps).unwrap_err().class,
        ErrorClass::TooManyColumns
    );
    let bad_sql = SelfCheck::Equal {
        a: "SELECT COUNT(*) AS n FROM invoices i".into(),
        b: "SELECT x.n FROM sqlite_master x".into(),
    };
    assert_eq!(
        validate_check(&bad_sql, &s, &public(), &ps)
            .unwrap_err()
            .class,
        ErrorClass::UnknownTable
    );
}

#[test]
fn error_class_names_round_trip() {
    let all = [
        "syntax",
        "not_select",
        "multiple_statements",
        "unknown_table",
        "unknown_column",
        "function_not_allowed",
        "construct_not_allowed",
        "literal_not_allowed",
        "param_misuse",
        "param_type",
        "null_masking",
        "too_many_joins",
        "too_deep",
        "too_many_columns",
        "template_slot",
        "runtime_error",
        "time_cap",
        "memory_cap",
        "step_cap",
        "check_failed",
    ];
    for n in all {
        let c = ErrorClass::from_str(n).unwrap_or_else(|| panic!("{n}"));
        assert_eq!(c.as_str(), n);
        assert_eq!(serde_json::to_string(&c).unwrap(), format!("\"{n}\""));
    }
    assert!(ErrorClass::from_str("empty_for_key").is_none());
    let e = MethodError {
        class: ErrorClass::UnknownColumn,
        detail: Some("email".into()),
    };
    let j = serde_json::to_string(&e).unwrap();
    assert_eq!(serde_json::from_str::<MethodError>(&j).unwrap(), e);
}

#[test]
fn parse_reply_schema() {
    let good = r#"{"method":"SELECT 1","template":"{rows()}","checks":[{"kind":"rows_between","min":1,"max":1},{"kind":"equal","a":"SELECT 1","b":"SELECT 1"}],"intent":"count"}"#;
    let r = parse_reply(good).unwrap();
    assert_eq!(r.method, "SELECT 1");
    assert_eq!(r.checks.len(), 2);
    assert_eq!(r.checks[0], SelfCheck::RowsBetween { min: 1, max: 1 });
    assert!(!r.needs_judgment);
    let back = serde_json::to_string(&r).unwrap();
    assert_eq!(parse_reply(&back).unwrap(), r);

    let judgment = r#"{"method":"","template":"","intent":"needs a person","needs_judgment":true}"#;
    let r = parse_reply(judgment).unwrap();
    assert!(r.needs_judgment && r.checks.is_empty());

    let missing_intent = r#"{"method":"SELECT 1","template":"x"}"#;
    assert_eq!(parse_reply(missing_intent).unwrap_err(), ErrorClass::Syntax);
    let extra = r#"{"method":"SELECT 1","template":"x","intent":"i","note":"hi"}"#;
    assert_eq!(parse_reply(extra).unwrap_err(), ErrorClass::Syntax);
    let bad_kind =
        r#"{"method":"SELECT 1","template":"x","intent":"i","checks":[{"kind":"guess"}]}"#;
    assert_eq!(parse_reply(bad_kind).unwrap_err(), ErrorClass::Syntax);
    assert_eq!(parse_reply("not json").unwrap_err(), ErrorClass::Syntax);
    let five = format!(
        r#"{{"method":"SELECT 1","template":"x","intent":"i","checks":[{}]}}"#,
        [r#"{"kind":"rows_between","min":1,"max":1}"#; 5].join(",")
    );
    assert_eq!(parse_reply(&five).unwrap_err(), ErrorClass::Syntax);
    let long_method = format!(
        r#"{{"method":"{}","template":"x","intent":"i"}}"#,
        "a".repeat(8193)
    );
    assert_eq!(parse_reply(&long_method).unwrap_err(), ErrorClass::Syntax);
    let long_template = format!(
        r#"{{"method":"x","template":"{}","intent":"i"}}"#,
        "a".repeat(4097)
    );
    assert_eq!(parse_reply(&long_template).unwrap_err(), ErrorClass::Syntax);
    let long_intent = format!(
        r#"{{"method":"x","template":"t","intent":"{}"}}"#,
        "ø".repeat(301)
    );
    assert_eq!(parse_reply(&long_intent).unwrap_err(), ErrorClass::Syntax);
    let ok_intent = format!(
        r#"{{"method":"x","template":"t","intent":"{}"}}"#,
        "ø".repeat(300)
    );
    assert!(parse_reply(&ok_intent).is_ok());
}

#[test]
fn plan_schema_is_json() {
    let v: serde_json::Value = serde_json::from_str(PLAN_SCHEMA).unwrap();
    assert_eq!(v["type"], "object");
    assert_eq!(v["additionalProperties"], false);
    assert_eq!(v["properties"]["method"]["maxLength"], 8192);
    assert_eq!(v["properties"]["template"]["maxLength"], 4096);
    assert_eq!(v["properties"]["intent"]["maxLength"], 300);
    assert_eq!(v["properties"]["checks"]["maxItems"], 4);
    let req: Vec<&str> = v["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    for f in ["method", "template", "intent"] {
        assert!(req.contains(&f), "{f}");
    }
}

#[test]
fn odd_unicode_never_panics() {
    let odd = ["İ", "\u{212A}", "ß", "ﬃ", "é\u{301}"];
    for w in odd {
        let long = w.repeat(200);
        for sql in [
            format!("SELECT c.id FROM {w} c"),
            format!("SELECT c.{w} FROM customers c"),
            format!("SELECT {w}(c.id) AS x FROM customers c"),
            format!("SELECT c.id FROM customers c WHERE c.city = '{w}'"),
            format!("SELECT c.id FROM \"{long}\" c"),
            format!("SELECT \"{long}\" AS x FROM customers c"),
            format!("SELECT c.id AS \"{w}\" FROM customers c"),
            format!("SELECT {w}"),
        ] {
            if let Err(e) = validate(&sql, &schema(), &public(), &params()) {
                if let Some(d) = &e.detail {
                    assert!(d.chars().count() <= 120);
                }
            }
        }
    }
}
