//! Plan 45 Task 1: the planner reply types and the SELECT-only SQL validator
//! (R45-1..R45-5, R45-8; coordinator ruling C-G: an allow-listed shape).

use saiife_shield::plan::{parse_reply, SelfCheck, PLAN_SCHEMA};
use saiife_shield::public::PublicValues;
use saiife_shield::schema::{
    Bound, ColType, ColumnClass, ColumnInfo, EntitySpec, Param, ParamType, Schema, TableInfo,
};
use saiife_shield::sql::{
    validate, validate_check, EntityFilter, ErrorClass, MethodError, ValidatedCheck,
};

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

/// The draft without the bound entity parameter.
fn no_entity() -> Vec<Param> {
    params().into_iter().skip(1).collect()
}

/// A bound entity parameter must be used by the method, so the draft holds
/// `p1` only when the method names it.
fn ps_for(sql: &str) -> Vec<Param> {
    if sql.contains(":p1") {
        params()
    } else {
        no_entity()
    }
}

fn ok(sql: &str) -> saiife_shield::sql::Validated {
    match validate(sql, &schema(), &public(), &ps_for(sql)) {
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
    class_of(sql, &schema(), &ps_for(sql))
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

const J: &str = "FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";

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
    // COUNT is not a nullable aggregate.
    let v = ok(&format!("SELECT COUNT(*) AS n, MAX(i.amount) AS top {J}"));
    assert_eq!(v.aggregates_nullable, vec![1]);
}

#[test]
fn entity_filters_and_count_only() {
    let v = ok(BALANCE);
    assert_eq!(
        v.entity_filters,
        vec![EntityFilter {
            param: "p1".into(),
            table: "customers".into(),
            key: "id".into(),
            linked: vec![("invoices".into(), "customer_id".into())],
        }]
    );
    assert!(!v.count_only);
    // COUNT-only: zero linked rows is a computed 0.
    let v = ok(&format!(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT i.status) AS k {J} AND i.status = 'open'"
    ));
    assert!(v.count_only);
    assert!(v.aggregates_nullable.is_empty());
    assert_eq!(v.entity_filters[0].linked.len(), 1);
    // A grouping column beside COUNT keeps count_only.
    let v = ok(&format!(
        "SELECT i.status, COUNT(*) AS n {J} GROUP BY i.status"
    ));
    assert!(v.count_only);
    // Arithmetic over COUNTs, a plain list or a bare pinned column is not
    // count-only.
    for sql in [
        format!("SELECT COUNT(*) / COUNT(i.id) AS r {J}"),
        format!("SELECT i.amount {J}"),
        format!("SELECT COUNT(*) AS n, c.credit_limit {J}"),
    ] {
        assert!(!ok(&sql).count_only, "{sql}");
    }
    // Linked through a CTE column: the origin is invoices.customer_id.
    let v = ok(
        "WITH t AS (SELECT k.customer_id AS cid, SUM(k.amount) AS s FROM invoices k \
         GROUP BY k.customer_id) \
         SELECT t.s FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1",
    );
    assert_eq!(
        v.entity_filters[0].linked,
        vec![("invoices".to_string(), "customer_id".to_string())]
    );
    prepares(&v.sql);
    // Pinned on the entity table alone: nothing linked; no entity, no filter.
    let v = ok("SELECT c.city FROM customers c WHERE c.id = :p1");
    assert!(v.entity_filters[0].linked.is_empty());
    assert!(ok("SELECT COUNT(*) AS n FROM invoices i")
        .entity_filters
        .is_empty());
}

#[test]
fn legitimate_methods_pass() {
    for sql in [
        BALANCE.to_string(),
        // Sum of a customer's invoices in Q3.
        format!("SELECT SUM(i.amount) AS total {J} AND i.issued >= :p3_from AND i.issued < :p3_to"),
        // Count of open invoices.
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.status = 'open'".to_string(),
        // A top-10 list.
        "SELECT c.first_name, SUM(i.amount) AS total FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.id, c.first_name ORDER BY total DESC LIMIT 10"
            .to_string(),
        // Per-month grouping.
        "SELECT strftime('%Y-%m', i.issued) AS month, COUNT(*) AS n FROM invoices i \
         GROUP BY month ORDER BY month"
            .to_string(),
        "SELECT date(i.issued, 'start of month') AS m, SUM(i.amount) AS s FROM invoices i \
         WHERE date(i.issued) >= '2026-01-01' GROUP BY date(i.issued, 'start of month')"
            .to_string(),
        // HAVING.
        "SELECT c.city, COUNT(*) AS n FROM customers c GROUP BY c.city HAVING COUNT(*) > 2"
            .to_string(),
        "SELECT DISTINCT c.city FROM customers c WHERE c.city IN (:p4) ORDER BY c.city".to_string(),
        "SELECT i.id, i.amount FROM invoices i WHERE i.amount >= 90 AND i.amount < -1.5 \
         AND i.status IN ('open', 'paid') AND i.issued <> :p5 LIMIT 5 OFFSET 10"
            .to_string(),
        format!("SELECT SUM(i.amount) / COUNT(*) AS mean, AVG(DISTINCT i.amount) AS a {J}"),
    ] {
        let v = ok(&sql);
        prepares(&v.sql);
    }
}

#[test]
fn wide_method_renders_and_prepares() {
    let sql = "WITH big AS (SELECT i.customer_id AS cid, SUM(i.amount) AS total \
         FROM invoices i WHERE i.issued >= :p3_from AND i.issued < :p3_to \
         GROUP BY i.customer_id HAVING SUM(i.amount) > :p2) \
         SELECT c.city, COUNT(DISTINCT c.id) AS n, AVG(b.total) AS avg_total, \
         MAX(b.total) AS top, SUM(b.total) / COUNT(*) AS mean \
         FROM customers c JOIN big b ON b.cid = c.id \
         WHERE c.city = :p4 GROUP BY c.city ORDER BY n DESC LIMIT 10 OFFSET 5";
    let v = ok(sql);
    assert_eq!(v.params_used, vec!["p3", "p2", "p4"]);
    assert!(v.entity_params.is_empty());
    assert_eq!(v.aggregates_nullable, vec![2, 3, 4]);
    prepares(&v.sql);
}

#[test]
fn aliases_map_back() {
    let s = aliased_schema();
    let v = validate(
        "SELECT c.town, COUNT(*) AS n FROM clients c GROUP BY c.town",
        &s,
        &public(),
        &no_entity(),
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
    let v = validate("SELECT town FROM clients", &s, &public(), &no_entity()).unwrap();
    assert!(v.sql.contains("AS \"town\""), "{}", v.sql);
    prepares(&v.sql);
    // The snapshot names are not the cloud's names.
    assert_eq!(
        class_of("SELECT c.city FROM clients c", &s, &no_entity()),
        ErrorClass::UnknownColumn
    );
    let e = validate("SELECT id FROM customers", &s, &public(), &no_entity()).unwrap_err();
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
    // Joins count across the CTEs and the outer block.
    let cte_joins = "WITH t AS (SELECT a.customer_id AS cid FROM invoices a \
        JOIN customers x ON x.id = a.customer_id JOIN invoices b ON b.customer_id = x.id \
        GROUP BY a.customer_id) \
        SELECT c.id FROM customers c JOIN t ON t.cid = c.id \
        JOIN invoices d ON d.customer_id = c.id JOIN invoices e ON e.customer_id = c.id";
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
            "WITH RECURSIVE r AS (SELECT c.id AS n FROM customers c) SELECT r.n FROM r",
            ConstructNotAllowed,
        ),
        (
            "SELECT CAST(c.id AS INTEGER) AS b FROM customers c",
            ConstructNotAllowed,
        ),
        // No subqueries anywhere (they were depth-capped; now refused).
        (
            "SELECT c.id FROM customers c WHERE c.id IN (SELECT a.customer_id FROM invoices a)",
            ConstructNotAllowed,
        ),
        (
            "SELECT t.n FROM (SELECT COUNT(*) AS n FROM invoices i) t",
            ConstructNotAllowed,
        ),
        ("SELECT COUNT(*) AS n", ConstructNotAllowed),
        (five_joins, TooManyJoins),
        (cte_joins, TooManyJoins),
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

/// Ruling C-G: masking routes are refused by the grammar, entity or not.
#[test]
fn grammar_refuses_masking_routes() {
    use ErrorClass::*;
    let n = "FROM invoices i";
    let cases: Vec<(String, ErrorClass)> = vec![
        // The rework spec's list.
        (
            format!("SELECT SUM(CASE WHEN c.id = :p1 THEN i.amount ELSE 0 END) AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT CASE WHEN SUM(i.amount) > 0 THEN SUM(i.amount) ELSE 0 END AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            "SELECT SUM(COALESCE(i.amount, 0)) AS owed FROM customers c LEFT JOIN invoices i \
             ON i.customer_id = c.id WHERE c.id = :p1"
                .to_string(),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(COALESCE(i.amount, 0)) AS owed {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT SUM(i.amount) NOT IN (SELECT k.amount FROM invoices k) AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT 0 AS owed, COUNT(*) AS n {J}"),
            LiteralNotAllowed,
        ),
        (format!("SELECT COUNT(*) + 0 AS n {J}"), LiteralNotAllowed),
        (
            format!("SELECT i.amount IN (SUM(i.amount), 1) AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount IN (SUM(i.amount), 1)"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount BETWEEN 1 AND 5"),
            ConstructNotAllowed,
        ),
        (
            "SELECT SUM(i.amount) AS x FROM invoices i JOIN customers c ON 1 = 1 \
             WHERE c.id = :p1"
                .to_string(),
            ConstructNotAllowed,
        ),
        (
            "SELECT SUM(i.amount) AS x FROM invoices i JOIN customers c ON c.id = i.amount \
             WHERE c.id = :p1"
                .to_string(),
            ConstructNotAllowed,
        ),
        (
            "WITH t AS (SELECT 0 AS z FROM invoices i) SELECT t.z FROM t".to_string(),
            LiteralNotAllowed,
        ),
        (
            "WITH t AS (SELECT i.customer_id AS cid, 0 AS z FROM invoices i \
             GROUP BY i.customer_id) \
             SELECT t.z FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1"
                .to_string(),
            LiteralNotAllowed,
        ),
        // Controller addendum (c).
        (
            format!("SELECT COUNT(*) * 0 + 1000 AS n {J}"),
            LiteralNotAllowed,
        ),
        (
            format!("SELECT julianday(i.issued) + COUNT(*) AS n {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT (1 IN (SUM(i.amount), 1)) + COUNT(*) AS n {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(c.id - c.id) AS n {J}"),
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.id \
             WHERE c.id = :p1"
                .to_string(),
            ConstructNotAllowed,
        ),
        // The old masking forms: each is outside the grammar now.
        (
            format!("SELECT COALESCE(SUM(i.amount), 0) AS owed {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT TOTAL(i.amount) AS owed {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT IFNULL(MAX(i.amount), 0) AS top {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT NULLIF(SUM(i.amount), 0) AS owed {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT IIF(SUM(i.amount) IS NULL, 0, 1) AS x {J}"),
            FunctionNotAllowed,
        ),
        (
            format!("SELECT SUM(i.amount) IS NULL AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount IS NOT NULL"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(i.amount) AND 0 AS x {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT CASE SUM(i.amount) WHEN 0 THEN 0 ELSE 1 END AS x {J}"),
            ConstructNotAllowed,
        ),
        (format!("SELECT 1 + 2 AS owed {J}"), LiteralNotAllowed),
        (
            format!("SELECT -SUM(i.amount) AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(i.amount) % 2 AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(i.amount) + i.amount AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(SUM(i.amount)) AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT MAX(i.amount, 0) AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT SUM(date(i.issued)) AS owed {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT strftime('%Y', 'now') AS y {J}"),
            LiteralNotAllowed,
        ),
        (
            format!("SELECT date(i.amount) AS y {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} OR i.status = 'open'"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount > i.id"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND 1 = 1"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount NOT IN (1, 2)"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.amount = NULL"),
            LiteralNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.issued >= date(:p5)"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} HAVING i.amount > 1"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} HAVING COUNT(*) > 1 OR COUNT(*) < 1"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {n} WHERE i.status IN ()"),
            ConstructNotAllowed,
        ),
    ];
    for (sql, want) in &cases {
        assert_eq!(refused(sql), *want, "{sql}");
    }
    // Refused with or without an entity parameter.
    for sql in [
        format!("SELECT COALESCE(SUM(i.amount), 0) AS s {n}"),
        format!("SELECT 0 AS owed, COUNT(*) AS n {n}"),
        "SELECT COUNT(*) AS n FROM invoices i JOIN invoices k ON 1 = 1".to_string(),
    ] {
        assert!(
            validate(&sql, &schema(), &public(), &no_entity()).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn joins_only_on_declared_key_pairs() {
    // The pair is customers.id <-> <word>_<key> = customer_id in another
    // table, checked by column origin, not by qualifier.
    for sql in [
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id",
        "SELECT c.id FROM invoices i JOIN customers c ON (c.id = i.customer_id) \
         AND i.customer_id = c.id",
        "SELECT c2.id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN customers c2 ON c2.id = i.customer_id",
    ] {
        prepares(&ok(sql).sql);
    }
    use ErrorClass::*;
    for sql in [
        "SELECT c.id FROM customers c JOIN invoices i ON i.id = c.id",
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.credit_limit",
        "SELECT c.id FROM customers c JOIN customers k ON k.id = c.id",
        "SELECT i.id FROM invoices i JOIN invoices k ON k.customer_id = i.customer_id",
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id AND 1 = 1",
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         AND i.status = 'open'",
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id > c.id",
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         OR i.customer_id = c.id",
        // The ON must link the joined source to one before it.
        "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN invoices k ON i.customer_id = c.id",
        "SELECT c.id FROM customers c LEFT JOIN invoices i ON i.customer_id = c.id",
        "SELECT c.id FROM customers c JOIN invoices i USING (id)",
        "SELECT c.id FROM customers c NATURAL JOIN invoices i",
    ] {
        assert_eq!(refused(sql), ConstructNotAllowed, "{sql}");
    }
    // Addendum (b): a CTE column joins only when it is a plain (grouped)
    // column, and its origin decides.
    for sql in [
        // An aggregate column is not a key.
        "WITH t AS (SELECT k.customer_id AS cid, COUNT(*) AS n FROM invoices k \
         GROUP BY k.customer_id) \
         SELECT c.id FROM customers c JOIN t ON t.n = c.id",
        // A plain column whose origin is not the FK, renamed to look like one.
        "WITH t AS (SELECT k.id AS customer_id FROM invoices k) \
         SELECT c.id FROM customers c JOIN t ON t.customer_id = c.id",
        // A date expression is not a key.
        "WITH t AS (SELECT date(k.issued) AS d FROM invoices k GROUP BY date(k.issued)) \
         SELECT c.id FROM customers c JOIN t ON t.d = c.id",
    ] {
        assert_eq!(refused(sql), ConstructNotAllowed, "{sql}");
    }
    let v = ok("WITH t AS (SELECT k.customer_id AS cid FROM invoices k) \
         SELECT c.id FROM customers c JOIN t ON t.cid = c.id");
    prepares(&v.sql);
}

#[test]
fn bare_columns_only_grouped_or_pinned() {
    use ErrorClass::*;
    // Addendum (a): a plain column in an aggregating block must be grouped,
    // except a column of the entity table pinned by `key = :pN` in the
    // outermost block.
    for sql in [
        // Sums all invoices for an arbitrary cid.
        "WITH t AS (SELECT k.customer_id AS cid, SUM(k.amount) AS s FROM invoices k) \
         SELECT t.s FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1",
        "SELECT c.city, COUNT(*) AS n FROM customers c",
        "SELECT i.amount, SUM(i.amount) AS s FROM invoices i GROUP BY i.status",
        // A column of the joined (non-pinned) table.
        "SELECT SUM(i.amount) AS s, i.status FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        // An aggregate only in ORDER BY or HAVING makes the block aggregating.
        "SELECT c.city, COUNT(*) AS n FROM customers c ORDER BY COUNT(*)",
        "SELECT c.city FROM customers c HAVING COUNT(*) > 1",
        // A date expression is grouped only as written.
        "SELECT strftime('%Y', i.issued) AS y, COUNT(*) AS n FROM invoices i \
         GROUP BY i.issued",
    ] {
        assert_eq!(refused(sql), ConstructNotAllowed, "{sql}");
    }
    for sql in [
        BALANCE,
        "SELECT c.city, COUNT(*) AS n FROM customers c GROUP BY c.city",
        "SELECT c.first_name, c.city, COUNT(i.id) AS n FROM invoices i JOIN customers c \
         ON c.id = i.customer_id WHERE c.id = :p1",
        "SELECT c.city FROM customers c GROUP BY c.city",
    ] {
        prepares(&ok(sql).sql);
    }
}

#[test]
fn entity_param_positions() {
    use ErrorClass::*;
    for (sql, want) in [
        // Only in the outermost WHERE.
        (
            "WITH t AS (SELECT c.id AS id FROM customers c WHERE c.id = :p1) \
             SELECT t.id FROM t",
            ParamMisuse,
        ),
        (
            "SELECT c.id, COUNT(*) AS n FROM customers c GROUP BY c.id HAVING COUNT(*) = :p1",
            ParamMisuse,
        ),
        // Through a CTE column, even one that came from the key.
        (
            "WITH t AS (SELECT c.id AS id FROM customers c) SELECT t.id FROM t \
             WHERE t.id = :p1",
            ParamMisuse,
        ),
        // A list of keys is not one pick.
        (
            "SELECT c.city FROM customers c WHERE c.id IN (:p1, :p1)",
            ParamMisuse,
        ),
        (
            "SELECT i.id FROM invoices i WHERE i.customer_id = :p1",
            ParamMisuse,
        ),
        (
            "SELECT SUM(i.amount) AS x FROM invoices i JOIN customers c \
             ON c.id = i.customer_id AND c.id = :p1",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.id = :p1 AS x FROM customers c",
            ConstructNotAllowed,
        ),
        (
            "SELECT SUM(i.amount) AS x FROM invoices i JOIN customers c \
             ON c.id = i.customer_id WHERE NOT (c.id = :p1)",
            ConstructNotAllowed,
        ),
    ] {
        assert_eq!(refused(sql), want, "{sql}");
    }
    // A bound entity the method does not use is a method that ignores the
    // question's subject.
    assert_eq!(
        class_of(
            "SELECT SUM(i.amount) AS s FROM invoices i",
            &schema(),
            &params()
        ),
        ParamMisuse
    );
    // Unbound, it is not required.
    let mut ps = params();
    ps[0].bound = None;
    assert!(validate(
        "SELECT SUM(i.amount) AS s FROM invoices i",
        &schema(),
        &public(),
        &ps
    )
    .is_ok());
    let v = ok(&format!(
        "SELECT SUM(i.amount) AS x {J} AND i.status = 'open' AND (c.id = :p1)"
    ));
    assert_eq!(v.entity_params, vec!["p1"]);
    prepares(&v.sql);
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
        (
            "SELECT c.city FROM customers c ORDER BY c.city NULLS FIRST",
            ConstructNotAllowed,
        ),
        (
            "SELECT c.city || c.city AS x FROM customers c",
            ConstructNotAllowed,
        ),
        (
            "SELECT \"count\"(c.id) AS x FROM customers c",
            FunctionNotAllowed,
        ),
    ];
    for (sql, want) in cases {
        assert_eq!(class_of(sql, &s, &ps), want, "{sql}");
    }
    // A quoted schema name is still the schema name.
    let v = ok("SELECT \"c\".\"city\" FROM \"customers\" \"c\"");
    prepares(&v.sql);
    // S1: a name the cloud never saw (the snapshot name behind an alias) is a
    // free name: the CTE is accepted and renders under the reserved prefix.
    let a = aliased_schema();
    let v = validate(
        "WITH customers AS (SELECT i.id AS id FROM invoices i) \
         SELECT x.id FROM customers x",
        &a,
        &public(),
        &no_entity(),
    )
    .unwrap();
    assert!(v.sql.contains("\"_p_customers\""), "{}", v.sql);
    prepares(&v.sql);
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
    ok("SELECT COUNT(*) AS n FROM invoices i WHERE date(i.issued) >= :p3_from");
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
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE :p2 = 5",
            ErrorClass::ParamType,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE \
             strftime('%Y-%m', i.issued) >= :p3_from",
            ErrorClass::ParamType,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE \
             strftime('%Y-%m', i.issued) = '2026-07'",
            LiteralNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE \
             date(i.issued, 'localtime') >= :p5",
            LiteralNotAllowed,
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

/// Outcome of `sql` as (class or "ok"), detail.
fn outcome(sql: &str, s: &Schema) -> (String, Option<String>) {
    match validate(sql, s, &public(), &ps_for(sql)) {
        Ok(_) => ("ok".into(), None),
        Err(e) => (e.class.as_str().into(), e.detail),
    }
}

#[test]
fn hidden_names_are_not_an_oracle() {
    // S1 / I4: `customers` and `city` are hidden behind `clients` / `town`.
    let a = aliased_schema();
    let pairs = [
        // CTE named like a hidden table vs a free name.
        (
            "WITH customers AS (SELECT i.id AS id FROM invoices i) SELECT x.id FROM customers x",
            "WITH zzfree AS (SELECT i.id AS id FROM invoices i) SELECT x.id FROM zzfree x",
        ),
        // Table alias named like a hidden table.
        (
            "SELECT customers.amount FROM invoices customers",
            "SELECT zzfree.amount FROM invoices zzfree",
        ),
        // CTE reference alias named like a hidden table.
        (
            "WITH t AS (SELECT i.id AS n FROM invoices i) SELECT customers.n FROM t customers",
            "WITH t AS (SELECT i.id AS n FROM invoices i) SELECT zzfree.n FROM t zzfree",
        ),
        // Output alias named like a hidden column, referenced.
        (
            "SELECT COUNT(*) AS city FROM clients c ORDER BY city",
            "SELECT COUNT(*) AS zzfree FROM clients c ORDER BY zzfree",
        ),
        (
            "SELECT c.segment, COUNT(*) AS city FROM clients c GROUP BY c.segment HAVING city > 1",
            "SELECT c.segment, COUNT(*) AS zzfree FROM clients c GROUP BY c.segment HAVING zzfree > 1",
        ),
        // Unknown hidden names fail exactly like unknown free names.
        ("SELECT c.city FROM clients c", "SELECT c.zzfree FROM clients c"),
        ("SELECT x.id FROM customers x", "SELECT x.id FROM zzfree x"),
    ];
    for (hidden, free) in pairs {
        let h = outcome(hidden, &a);
        let f = outcome(free, &a);
        assert_eq!(h.0, f.0, "{hidden} vs {free}");
        let norm = |d: Option<String>| {
            d.map(|d| {
                d.replace("zzfree", "N")
                    .replace("customers", "N")
                    .replace("city", "N")
            })
        };
        assert_eq!(norm(h.1), norm(f.1), "{hidden} vs {free}");
    }
    // Planner names render under the reserved prefix; no bare name is left
    // for SQLite to resolve.
    let v = validate(
        "SELECT COUNT(*) AS city FROM clients c ORDER BY city",
        &a,
        &public(),
        &no_entity(),
    )
    .unwrap();
    assert!(v.sql.contains("\"_p_c\""), "{}", v.sql);
    assert!(!v.sql.contains("ORDER BY \"city\""), "{}", v.sql);
    prepares(&v.sql);
    // A schema using the reserved prefix is refused, with no detail.
    let mut bad = schema();
    bad.tables[1].columns[2].name = "_p_amount".into();
    let e = validate("SELECT c.id FROM customers c", &bad, &public(), &params()).unwrap_err();
    assert_eq!(
        e,
        MethodError {
            class: ErrorClass::RuntimeError,
            detail: None
        }
    );
    let mut bad = schema();
    bad.tables[1].name = "_P_inv".into();
    let e = validate("SELECT c.id FROM customers c", &bad, &public(), &params()).unwrap_err();
    assert_eq!(e.class, ErrorClass::RuntimeError);
}

#[test]
fn rowid_names_and_duplicate_outputs_refused() {
    use ErrorClass::*;
    for sql in [
        // M5: planner names that SQLite could bind to the implicit rowid.
        "SELECT COUNT(*) AS rowid FROM customers c GROUP BY rowid",
        "SELECT COUNT(*) AS OID FROM customers c ORDER BY OID",
        "SELECT COUNT(*) AS _rowid_ FROM customers c",
        "SELECT r.id FROM customers rowid JOIN customers r ON r.id = rowid.id",
        "WITH oid AS (SELECT c.id AS id FROM customers c) SELECT o.id FROM oid o",
        // M6: duplicate top-level output names (ignoring case).
        "SELECT c.id, i.id FROM customers c JOIN invoices i ON i.customer_id = c.id",
        "SELECT c.id AS n, COUNT(*) AS N FROM customers c GROUP BY c.id",
    ] {
        assert_eq!(refused(sql), ConstructNotAllowed, "{sql}");
    }
    ok("SELECT c.id, i.id AS invoice_id FROM customers c JOIN invoices i ON i.customer_id = c.id");
}
