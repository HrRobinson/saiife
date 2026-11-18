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

/// customers(id, first_name, last_name, city, credit_limit, segment, cpr,
/// email, phone), invoices(id, customer_id, amount, status, issued,
/// discount), payments(id, customer_id, invoice_id, amount, paid); entities
/// customers and invoices.
///
/// R45-13 (owner ruling 2026-11-18): names, `cpr`, `email` and `phone` are
/// Identifier columns. The key and FK columns are classed Sensitive here, so
/// the many tests that output a key as scaffolding keep testing their own
/// rule (G1 key columns, joins, names); [`ident_keys`] classes them
/// Identifier, as plan 43's classifier does for a unique `id` column.
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
                    col("id", Integer, Sensitive),
                    col("first_name", Text, Identifier),
                    col("last_name", Text, Identifier),
                    col("city", Text, Quasi),
                    col("credit_limit", Real, Sensitive),
                    col("segment", Text, Public),
                    col("cpr", Text, Identifier),
                    col("email", Text, Identifier),
                    col("phone", Text, Identifier),
                ],
            },
            TableInfo {
                name: "invoices".into(),
                alias: None,
                rows: 5000,
                columns: vec![
                    col("id", Integer, Sensitive),
                    col("customer_id", Integer, Sensitive),
                    col("amount", Real, Sensitive),
                    col("status", Text, Public),
                    col("issued", Date, Quasi),
                    col("discount", Real, Sensitive),
                ],
            },
            TableInfo {
                name: "payments".into(),
                alias: None,
                rows: 3000,
                columns: vec![
                    col("id", Integer, Sensitive),
                    col("customer_id", Integer, Sensitive),
                    col("invoice_id", Integer, Sensitive),
                    col("amount", Real, Sensitive),
                    col("paid", Date, Quasi),
                ],
            },
        ],
        entities: vec![
            EntitySpec {
                table: "customers".into(),
                key: "id".into(),
                names: vec!["first_name".into(), "last_name".into()],
                show: vec!["city".into()],
                word: "customer".into(),
                word_da: "kunde".into(),
            },
            EntitySpec {
                table: "invoices".into(),
                key: "id".into(),
                names: vec![],
                show: vec![],
                word: "invoice".into(),
                word_da: "faktura".into(),
            },
        ],
        joins: vec![],
    }
}

/// The fixture with its key and FK columns classed Identifier.
fn ident_keys() -> Schema {
    let mut s = schema();
    for t in &mut s.tables {
        for c in &mut t.columns {
            if c.name == "id" || c.name.ends_with("_id") {
                c.class = ColumnClass::Identifier;
            }
        }
    }
    s
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
        plain("p6", ParamType::Integer),
        plain(
            "p7",
            ParamType::Text {
                table: "customers".into(),
                column: "id".into(),
            },
        ),
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
         credit_limit REAL, segment TEXT, cpr TEXT, email TEXT, phone TEXT);\
         CREATE TABLE invoices(id INTEGER, customer_id INTEGER, amount REAL, status TEXT, \
         issued TEXT, discount REAL);\
         CREATE TABLE payments(id INTEGER, customer_id INTEGER, invoice_id INTEGER, \
         amount REAL, paid TEXT);",
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
        format!("SELECT COUNT(*) - COUNT(DISTINCT i.status) AS r {J}"),
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
        "SELECT c.id, c.city, SUM(i.amount) AS total FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.id, c.city ORDER BY total DESC LIMIT 10"
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
         AND i.status IN ('open', 'paid') AND i.issued <> :p5 LIMIT 5"
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
         MAX(b.total) AS top, MIN(b.total) AS low \
         FROM customers c JOIN big b ON b.cid = c.id \
         WHERE c.city = :p4 GROUP BY c.city ORDER BY n DESC LIMIT 10";
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
    // Four joins without fan-out: two per-customer CTEs, each with a join.
    let four_joins = "WITH inv AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s \
        FROM invoices i JOIN customers x ON x.id = i.customer_id GROUP BY i.customer_id), \
        pay AS (SELECT p.customer_id AS cid, SUM(p.amount) AS s FROM payments p \
        JOIN customers y ON y.id = p.customer_id GROUP BY p.customer_id) \
        SELECT c.id FROM customers c JOIN inv ON inv.cid = c.id JOIN pay ON pay.cid = c.id";
    prepares(&ok(four_joins).sql);
    // Joins count across the CTEs and the outer block.
    let cte_joins = four_joins.replace(
        "JOIN pay ON pay.cid = c.id",
        "JOIN pay ON pay.cid = c.id JOIN payments q ON q.customer_id = c.id",
    );
    let five_joins = "SELECT c.id FROM customers c JOIN invoices a ON a.customer_id = c.id \
        JOIN invoices b ON b.customer_id = c.id JOIN invoices d ON d.customer_id = c.id \
        JOIN invoices e ON e.customer_id = c.id JOIN invoices f ON f.customer_id = c.id";
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
        (&cte_joins, TooManyJoins),
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
        // Ruling F-k: `IS [NOT] NULL` only as a WHERE conjunct on a plain
        // non-key column (see `is_null_where_conjunct`).
        (
            format!("SELECT COUNT(*) AS n {J} HAVING SUM(i.amount) IS NOT NULL"),
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
        "SELECT c.credit_limit, c.city, COUNT(i.amount) AS n FROM invoices i JOIN customers c \
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
        ("SELECT c.issued FROM customers AS c", UnknownColumn),
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
    ok(
        "SELECT COUNT(*) AS n FROM invoices i WHERE date(i.issued) >= :p3_from \
        AND date(i.issued) < :p3_to",
    );
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
        // Plan 44 M9 / plan 45 final review M7: a date range is never a
        // count threshold.
        (
            "SELECT c.city, COUNT(*) AS n FROM customers c GROUP BY c.city \
             HAVING COUNT(*) > :p3_from",
            ErrorClass::ParamType,
        ),
        (
            "SELECT c.city, COUNT(*) AS n FROM customers c GROUP BY c.city \
             HAVING COUNT(*) > :p3",
            ParamMisuse,
        ),
    ] {
        assert_eq!(refused(sql), want, "{sql}");
    }
}

#[test]
fn date_range_needs_both_halves() {
    // Plan 45 final review part 3 (ruling F-h): "in Q3 2026" applied as
    // `issued >= :p3_from` alone counts everything after July 1st.
    for sql in [
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3_from",
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued < :p3_to",
        "SELECT SUM(i.amount) AS total FROM invoices i \
         JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.issued >= :p3_from",
        "WITH t AS (SELECT i.customer_id AS cid, COUNT(*) AS n FROM invoices i \
         WHERE i.issued < :p3_to GROUP BY i.customer_id) SELECT SUM(t.n) AS n FROM t",
    ] {
        let e = validate(sql, &schema(), &public(), &ps_for(sql)).unwrap_err();
        assert_eq!(e.class, ErrorClass::ParamMisuse, "{sql}");
        assert_eq!(e.detail, None, "{sql}");
    }
    // Bound or not: the shape is the method's, not the binding's.
    let mut bound = no_entity();
    bound[1].bound = Some(Bound::DateRange("2026-07-01".into(), "2026-10-01".into()));
    let sql = "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3_from";
    assert_eq!(class_of(sql, &schema(), &bound), ErrorClass::ParamMisuse);
    // Both halves: ok, in either operand order.
    let sql =
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= :p3_from AND i.issued < :p3_to";
    let v = validate(sql, &schema(), &public(), &bound).unwrap();
    assert_eq!(v.params_used, vec!["p3"]);
    ok("SELECT COUNT(*) AS n FROM invoices i WHERE :p3_to > i.issued AND :p3_from <= i.issued");
}

#[test]
fn identifier_output_owner_ruling() {
    // R45-13, owner ruling 2026-11-18 + ruling F-j: exact mode never prints
    // a value of an Identifier column.
    use ErrorClass::*;
    let ident = |sql: &str, s: &Schema| {
        let e = validate(sql, s, &public(), &ps_for(sql)).unwrap_err();
        assert_eq!(e.class, IdentifierOutput, "{sql}");
        assert_eq!(e.detail, None, "{sql}");
    };
    for sql in [
        // The owner's cases.
        "SELECT c.cpr FROM customers c",
        "SELECT c.email FROM customers c",
        "SELECT c.phone FROM customers c",
        "SELECT c.cpr FROM customers c WHERE c.id = :p1",
        // Names are Identifier columns too.
        "SELECT c.first_name, c.last_name FROM customers c WHERE c.id = :p1",
        // Through an expression: a function outside the allow-list over one
        // is identifier_output, not function_not_allowed (class precedence).
        "SELECT substr(c.cpr, 1, 6) AS x FROM customers c",
        "SELECT lower(c.email) AS x FROM customers c",
        "SELECT c.cpr || '' AS x FROM customers c",
        "SELECT CASE WHEN c.phone IS NULL THEN 0 ELSE 1 END AS x FROM customers c",
        "SELECT substr(c.cpr, 1, 6) AS x FROM customers c WHERE c.id = :p1",
        // MIN / MAX return one of its values (F-j).
        "SELECT MIN(c.email) AS m FROM customers c",
        "SELECT MAX(c.cpr) AS m FROM customers c WHERE c.city = :p4",
        "SELECT c.city, MAX(c.phone) AS m FROM customers c GROUP BY c.city",
        // GROUP BY it and output it.
        "SELECT c.email, COUNT(*) AS n FROM customers c GROUP BY c.email",
        // Through a CTE column, by origin.
        "WITH t AS (SELECT c.email AS e FROM customers c) SELECT t.e FROM t",
        "WITH t AS (SELECT c.city AS city, MIN(c.phone) AS p FROM customers c \
         GROUP BY c.city) SELECT t.city, t.p FROM t",
        "WITH t AS (SELECT c.cpr AS k, COUNT(*) AS n FROM customers c GROUP BY c.cpr) \
         SELECT t.k, t.n FROM t",
        "WITH t AS (SELECT c.cpr AS k FROM customers c) SELECT MAX(t.k) AS m FROM t",
        // Through an output alias referenced again.
        "SELECT c.email AS contact FROM customers c ORDER BY contact",
    ] {
        ident(sql, &schema());
    }
    // A substr in a CTE is refused there too.
    ident(
        "WITH t AS (SELECT substr(c.cpr, 1, 6) AS d FROM customers c) SELECT COUNT(*) AS n FROM t",
        &schema(),
    );
    // A key classed Identifier (plan 43 does this for a unique `id`): a plain
    // output, and MIN/MAX over it (before G1 would say construct).
    let k = ident_keys();
    for sql in [
        "SELECT c.id FROM customers c",
        "SELECT i.id, i.amount FROM invoices i WHERE i.amount > :p2",
        "SELECT i.customer_id, SUM(i.amount) AS s FROM invoices i GROUP BY i.customer_id",
        "SELECT MIN(c.id) AS m FROM customers c",
        "WITH t AS (SELECT i.customer_id AS cid FROM invoices i GROUP BY i.customer_id) \
         SELECT t.cid FROM t",
    ] {
        ident(sql, &k);
    }
    // Name and literal classes keep their class.
    for (sql, want) in [
        (
            "SELECT COUNT(DISTINCT c.email) + 1 AS x FROM customers c",
            LiteralNotAllowed,
        ),
        ("SELECT c.zzz FROM customers c", UnknownColumn),
    ] {
        assert_eq!(refused(sql), want, "{sql}");
    }
    // Allowed (owner + F-j): COUNT, COUNT DISTINCT, IS [NOT] NULL, WHERE
    // comparisons, GROUP BY without output, joins on an Identifier key.
    for sql in [
        "SELECT COUNT(DISTINCT c.email) AS n FROM customers c",
        "SELECT COUNT(c.phone) AS n FROM customers c",
        "SELECT COUNT(*) AS n FROM customers c WHERE c.phone IS NULL",
        "SELECT c.city, COUNT(*) AS n FROM customers c WHERE c.email IS NOT NULL GROUP BY c.city",
        "SELECT COUNT(*) AS n FROM customers c GROUP BY c.email",
        "SELECT c.city, COUNT(*) AS n FROM customers c GROUP BY c.city, c.cpr",
        "WITH t AS (SELECT c.email AS e, COUNT(*) AS n FROM customers c GROUP BY c.email) \
         SELECT COUNT(*) AS k, MAX(t.n) AS most FROM t",
        "WITH t AS (SELECT c.cpr AS k FROM customers c) SELECT COUNT(DISTINCT t.k) AS n FROM t",
        "SELECT COUNT(*) AS n FROM customers c ORDER BY n",
    ] {
        prepares(&ok(sql).sql);
    }
    // A WHERE comparison with an Identifier column.
    let mut ps = no_entity();
    ps.push(Param {
        name: "p9".into(),
        ty: saiife_shield::schema::ParamType::Text {
            table: "customers".into(),
            column: "email".into(),
        },
        bound: None,
        display: String::new(),
    });
    let sql = "SELECT COUNT(*) AS n FROM customers c WHERE c.email = :p9";
    prepares(&validate(sql, &schema(), &public(), &ps).unwrap().sql);
    for sql in [
        "SELECT SUM(i.amount) AS s FROM invoices i JOIN customers c ON c.id = i.customer_id \
         WHERE c.id = :p1",
        "SELECT COUNT(DISTINCT i.customer_id) AS n FROM invoices i",
        "SELECT c.city, SUM(i.amount) AS s FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.id, c.city ORDER BY s DESC LIMIT 5",
    ] {
        match validate(sql, &k, &public(), &ps_for(sql)) {
            Ok(v) => prepares(&v.sql),
            Err(e) => panic!("{sql}: refused {e:?}"),
        }
    }
    // The class: its name, the planner list, the user's reason (verbatim).
    assert_eq!(IdentifierOutput.as_str(), "identifier_output");
    assert_eq!(
        IdentifierOutput.user_reason(),
        Some("Data Shield doesn't show ID numbers. Revealing one needs a touch on your key.")
    );
    assert_eq!(
        saiife_shield::sql::IDENTIFIER_OUTPUT_REASON,
        IdentifierOutput.user_reason().unwrap()
    );
    assert_eq!(ConstructNotAllowed.user_reason(), None);
    assert!(saiife_shield::firewall::PLANNER_ERROR_CLASSES.contains(&"identifier_output"));
    // A self-check side is held to the same rule.
    let c = saiife_shield::plan::SelfCheck::Equal {
        a: "SELECT MAX(c.cpr) AS m FROM customers c".into(),
        b: "SELECT MIN(c.cpr) AS m FROM customers c".into(),
    };
    let e = validate_check(&c, &schema(), &public(), &no_entity()).unwrap_err();
    assert_eq!(e.class, IdentifierOutput);
}

#[test]
fn identifier_sums_dates_and_arithmetic() {
    // Final review part 5, item 4 (ruling F-j): SUM / AVG, date / strftime
    // and arithmetic over an Identifier column yield it.
    let mut s = schema();
    for (t, c) in [("customers", "credit_limit"), ("invoices", "issued")] {
        let col = s
            .tables
            .iter_mut()
            .find(|x| x.name == t)
            .and_then(|x| x.columns.iter_mut().find(|y| y.name == c))
            .unwrap();
        col.class = ColumnClass::Identifier;
    }
    for sql in [
        "SELECT SUM(c.credit_limit) AS s FROM customers c",
        "SELECT AVG(c.credit_limit) AS a FROM customers c",
        "SELECT c.city, SUM(c.credit_limit) AS s FROM customers c GROUP BY c.city",
        "SELECT date(i.issued) AS d FROM invoices i",
        "SELECT date(i.issued, 'start of month') AS d FROM invoices i",
        "SELECT strftime('%Y', i.issued) AS y FROM invoices i",
        "SELECT strftime('%Y-%m', i.issued) AS m, COUNT(*) AS n FROM invoices i \
         GROUP BY strftime('%Y-%m', i.issued)",
        "SELECT SUM(c.credit_limit) - COUNT(*) AS x FROM customers c",
        "SELECT SUM(c.credit_limit) / COUNT(*) AS x FROM customers c",
        "SELECT COUNT(*) * AVG(c.credit_limit) AS x FROM customers c",
        "WITH t AS (SELECT c.city AS city, SUM(c.credit_limit) AS s FROM customers c \
         GROUP BY c.city) SELECT t.city, t.s FROM t",
        "WITH t AS (SELECT date(i.issued) AS d FROM invoices i GROUP BY date(i.issued)) \
         SELECT t.d FROM t",
    ] {
        let e = validate(sql, &s, &public(), &ps_for(sql)).unwrap_err();
        assert_eq!(e.class, ErrorClass::IdentifierOutput, "{sql}");
    }
    // Counting them, filtering or grouping by them without output: allowed.
    for sql in [
        "SELECT COUNT(DISTINCT c.credit_limit) AS n FROM customers c",
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.issued >= '2026-01-01'",
        "SELECT COUNT(*) AS n FROM invoices i GROUP BY strftime('%Y', i.issued)",
    ] {
        match validate(sql, &s, &public(), &ps_for(sql)) {
            Ok(v) => prepares(&v.sql),
            Err(e) => panic!("{sql}: refused {e:?}"),
        }
    }
}

#[test]
fn is_null_where_conjunct() {
    // Ruling F-k: `t.c IS [NOT] NULL` on a plain column, WHERE only
    // ("customers without a phone").
    for sql in [
        "SELECT COUNT(*) AS n FROM customers c WHERE c.phone IS NULL",
        "SELECT COUNT(*) AS n FROM customers c WHERE c.phone IS NOT NULL",
        "SELECT COUNT(*) AS n FROM invoices i WHERE i.amount IS NOT NULL AND i.status = 'open'",
        "SELECT COUNT(*) AS n FROM customers c WHERE (c.email IS NULL) AND c.city = :p4",
        "WITH t AS (SELECT c.city AS city, COUNT(*) AS n FROM customers c \
         WHERE c.phone IS NULL GROUP BY c.city) SELECT t.city, t.n FROM t",
        "SELECT SUM(i.amount) AS s FROM invoices i JOIN customers c ON c.id = i.customer_id \
         WHERE c.id = :p1 AND i.issued IS NULL",
    ] {
        let v = ok(sql);
        assert!(
            v.sql.contains(" IS NULL") || v.sql.contains(" IS NOT NULL"),
            "{}",
            v.sql
        );
        prepares(&v.sql);
    }
    use ErrorClass::*;
    for (sql, want) in [
        // A key / FK column stays structural (G1).
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE i.customer_id IS NULL",
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM customers c WHERE c.id IS NOT NULL",
            ConstructNotAllowed,
        ),
        // Not a plain column.
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE date(i.issued) IS NULL",
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE :p2 IS NULL",
            ParamMisuse,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i WHERE NULL IS NULL",
            LiteralNotAllowed,
        ),
        // Not in HAVING, the SELECT list, an ON, or under NOT / OR.
        (
            "SELECT COUNT(*) AS n FROM invoices i HAVING COUNT(*) IS NOT NULL",
            ConstructNotAllowed,
        ),
        (
            "SELECT i.amount IS NULL AS x FROM invoices i",
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM invoices i JOIN customers c \
             ON c.id = i.customer_id AND c.phone IS NULL",
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM customers c WHERE NOT c.phone IS NULL",
            ConstructNotAllowed,
        ),
        (
            "SELECT COUNT(*) AS n FROM customers c WHERE c.phone IS NULL OR c.email IS NULL",
            ConstructNotAllowed,
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
        b: "SELECT COUNT(i.amount) AS n FROM invoices i".into(),
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
        a: "SELECT COUNT(*) AS n, MAX(i.amount) AS m FROM invoices i".into(),
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
        "identifier_output",
        "template_slot",
        "runtime_error",
        "time_cap",
        "memory_cap",
        "step_cap",
        "check_failed",
        "empty_result",
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

// ---- round 3 (findings r3) ----

/// The schema with the FK column `invoices.customer_id` renamed to
/// `snapshot` (hidden) and shown to the cloud as `alias`.
fn fk_schema(snapshot: &str, alias: Option<&str>) -> Schema {
    let mut s = schema();
    s.tables[1].columns[1].name = snapshot.into();
    s.tables[1].columns[1].alias = alias.map(Into::into);
    s
}

fn outcome_in(sql: &str, s: &Schema) -> String {
    match validate(sql, s, &public(), &ps_for(sql)) {
        Ok(_) => "ok".into(),
        Err(e) => e.class.as_str().into(),
    }
}

#[test]
fn key_pairs_use_cloud_names() {
    // F1: the C-G1 pair is decided on cloud names only; the snapshot name
    // behind an alias never changes the outcome.
    let x = "SELECT c.id FROM customers c JOIN invoices i ON i.x = c.id";
    let a = outcome_in(x, &fk_schema("customer_id", Some("x")));
    let b = outcome_in(x, &fk_schema("cust_ref", Some("x")));
    assert_eq!(
        (a.as_str(), b.as_str()),
        ("construct_not_allowed", "construct_not_allowed")
    );
    let y = "SELECT c.id FROM customers c JOIN invoices i ON i.customer_id = c.id";
    let a = outcome_in(y, &fk_schema("customer_id", None));
    let b = outcome_in(y, &fk_schema("cust_ref", Some("customer_id")));
    assert_eq!((a.as_str(), b.as_str()), ("ok", "ok"));
    // The key's cloud name counts too: `customer_<cloud key>`.
    let mut k = schema();
    k.tables[0].columns[0].alias = Some("nr".into());
    assert_eq!(
        outcome_in(
            "SELECT c.nr FROM customers c JOIN invoices i ON i.customer_id = c.nr",
            &k
        ),
        "construct_not_allowed"
    );
    k.tables[1].columns[1].alias = Some("customer_nr".into());
    assert_eq!(
        outcome_in(
            "SELECT c.nr FROM customers c JOIN invoices i ON i.customer_nr = c.nr",
            &k
        ),
        "ok"
    );
}

#[test]
fn no_literals_on_keys_and_type_mismatch() {
    // F2: a literal on an entity key or an FK column defeats the pin.
    use ErrorClass::*;
    for sql in [
        format!("SELECT COUNT(*) AS n {J} AND c.id = 7"),
        format!("SELECT COUNT(*) AS n {J} AND c.id IN (7, 8)"),
        format!("SELECT COUNT(*) AS n {J} AND c.id > -1"),
        format!("SELECT COUNT(*) AS n {J} AND i.customer_id = 7"),
        format!("SELECT COUNT(*) AS n {J} AND i.customer_id <> 0"),
        format!("SELECT COUNT(*) AS n {J} AND i.id = 3"),
        "SELECT COUNT(*) AS n FROM payments p WHERE p.invoice_id = 3".to_string(),
        "WITH t AS (SELECT i.customer_id AS cid FROM invoices i) \
         SELECT t.cid FROM t WHERE t.cid = 5"
            .to_string(),
        // Type mismatches.
        "SELECT c.id FROM customers c WHERE c.city = 5".to_string(),
        "SELECT i.id FROM invoices i WHERE i.issued > 3".to_string(),
        "SELECT i.id FROM invoices i WHERE i.amount = '2026-01-01'".to_string(),
        "SELECT i.status, COUNT(*) AS n FROM invoices i GROUP BY i.status \
         HAVING COUNT(*) > '2026-01-01'"
            .to_string(),
        "SELECT i.status, MAX(i.issued) AS m FROM invoices i GROUP BY i.status \
         HAVING MAX(i.issued) > 5"
            .to_string(),
    ] {
        assert_eq!(refused(&sql), LiteralNotAllowed, "{sql}");
    }
    for sql in [
        "SELECT i.id FROM invoices i WHERE i.amount >= 90 AND i.status = 'open' \
         AND i.issued >= '2026-01-01'",
        "SELECT i.status, COUNT(*) AS n FROM invoices i GROUP BY i.status HAVING COUNT(*) > 2",
    ] {
        prepares(&ok(sql).sql);
    }
}

#[test]
fn join_fan_out_refused() {
    // F3: a join must not repeat the rows an aggregate reads.
    let k = "FROM customers c JOIN invoices i ON i.customer_id = c.id";
    for sql in [
        // Two children of one key; one table twice.
        "SELECT SUM(i.amount) AS s FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN invoices j ON j.customer_id = c.id WHERE c.id = :p1"
            .to_string(),
        "SELECT SUM(i.amount) - SUM(p.amount) AS owed FROM customers c \
         JOIN invoices i ON i.customer_id = c.id JOIN payments p ON p.customer_id = c.id \
         WHERE c.id = :p1"
            .to_string(),
        "SELECT COUNT(*) AS n FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN payments p ON p.customer_id = c.id WHERE c.id = :p1"
            .to_string(),
        "SELECT c2.id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN customers c2 ON c2.id = i.customer_id"
            .to_string(),
        "SELECT i.id, j.id AS j_id FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN invoices j ON j.customer_id = c.id"
            .to_string(),
        // An aggregate over a column the join repeats.
        format!("SELECT SUM(c.credit_limit) AS s {k}"),
        format!("SELECT AVG(c.credit_limit) AS s {k}"),
        format!("SELECT COUNT(c.city) AS s {k}"),
        format!("SELECT SUM(DISTINCT c.credit_limit) AS s {k}"),
        "SELECT SUM(i.amount) AS s FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN payments p ON p.invoice_id = i.id"
            .to_string(),
        // Laundered through a CTE column.
        "WITH t AS (SELECT c.credit_limit AS cl, i.customer_id AS cid FROM customers c \
         JOIN invoices i ON i.customer_id = c.id) SELECT SUM(t.cl) AS s FROM t"
            .to_string(),
        // A CTE key side that is not one row per key.
        "WITH t AS (SELECT c.id AS cid FROM customers c JOIN invoices i \
         ON i.customer_id = c.id) \
         SELECT SUM(p.amount) AS s FROM t JOIN payments p ON p.customer_id = t.cid"
            .to_string(),
        // One join linking to two earlier sources.
        "SELECT COUNT(*) AS n FROM customers c JOIN invoices i ON i.customer_id = c.id \
         JOIN payments p ON p.customer_id = c.id AND p.invoice_id = i.id"
            .to_string(),
    ] {
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    // Allowed: MIN/MAX/COUNT(*)/COUNT(DISTINCT) over the key side, a chain,
    // and the two-child balance through per-key CTEs.
    for sql in [
        format!(
            "SELECT MIN(c.credit_limit) AS m, MAX(c.credit_limit) AS x, COUNT(*) AS n, \
             COUNT(DISTINCT c.id) AS k {k}"
        ),
        "SELECT SUM(p.amount) AS s, COUNT(*) AS n FROM customers c \
         JOIN invoices i ON i.customer_id = c.id JOIN payments p ON p.invoice_id = i.id \
         WHERE c.id = :p1"
            .to_string(),
        BALANCE.to_string(),
    ] {
        prepares(&ok(&sql).sql);
    }
    let v = ok(
        "WITH inv AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s FROM invoices i \
         GROUP BY i.customer_id), \
         pay AS (SELECT p.customer_id AS cid, SUM(p.amount) AS s FROM payments p \
         GROUP BY p.customer_id) \
         SELECT SUM(inv.s) AS invoiced, SUM(pay.s) AS paid FROM customers c \
         JOIN inv ON inv.cid = c.id JOIN pay ON pay.cid = c.id WHERE c.id = :p1",
    );
    assert_eq!(
        v.entity_filters[0].linked,
        vec![
            ("invoices".to_string(), "customer_id".to_string()),
            ("payments".to_string(), "customer_id".to_string())
        ]
    );
    assert_eq!(v.aggregates_nullable, vec![0, 1]);
    prepares(&v.sql);
}

#[test]
fn cte_bodies_have_no_order_or_limit() {
    // F4: a CTE with LIMIT 1 can make a COUNT 0 for an existing entity.
    for tail in ["ORDER BY i.customer_id", "LIMIT 1", "LIMIT 1 OFFSET 2"] {
        let sql = format!(
            "WITH t AS (SELECT i.customer_id AS cid FROM invoices i {tail}) \
             SELECT COUNT(*) AS n FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1"
        );
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
}

#[test]
fn identical_arith_operands_refused() {
    // F5: `x - x` is a constant whatever the data.
    for sql in [
        "SELECT SUM(c.credit_limit) - SUM(c.credit_limit) AS z FROM customers c",
        "SELECT SUM(i.amount) / SUM(i.amount) AS z FROM invoices i",
        "SELECT (SUM(i.amount)) - SUM(i.amount) AS z FROM invoices i",
        "SELECT COUNT(*) - COUNT(*) AS z FROM invoices i",
    ] {
        assert_eq!(refused(sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    ok("SELECT SUM(i.amount) - MIN(i.amount) AS z FROM invoices i");
}

#[test]
fn key_columns_are_structural() {
    // G1: an entity key or FK column (by origin, through CTEs) appears only
    // in a key-pair ON, the entity pin, GROUP BY, a plain output column or
    // COUNT(DISTINCT col). Anywhere else it can defeat the pin.
    use ErrorClass::*;
    let cte = "WITH t AS (SELECT i.customer_id AS cid FROM invoices i GROUP BY i.customer_id)";
    for (sql, want) in [
        // Literal inside an aggregate in HAVING (CTE and outermost).
        (
            "WITH t AS (SELECT i.customer_id AS cid, COUNT(*) AS k FROM invoices i \
             GROUP BY i.customer_id HAVING MIN(i.customer_id) = 7) \
             SELECT COUNT(*) AS n FROM customers c JOIN t ON c.id = t.cid WHERE c.id = :p1"
                .to_string(),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} HAVING MIN(c.id) = 7"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} HAVING MAX(i.customer_id) > :p6"),
            ConstructNotAllowed,
        ),
        // Non-entity params on a key or FK column.
        (
            format!("SELECT COUNT(*) AS n {J} AND i.customer_id = :p6"),
            ParamMisuse,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND c.id = :p6"),
            ParamMisuse,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.customer_id <> :p6"),
            ParamMisuse,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND i.customer_id = :p2"),
            ParamMisuse,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} AND c.id IN (:p6)"),
            ParamMisuse,
        ),
        (
            format!(
                "SELECT COUNT(*) AS n {J} AND i.issued >= :p3_from AND i.issued < :p3_to \
                 AND i.id < :p6"
            ),
            ParamMisuse,
        ),
        (
            format!("{cte} SELECT COUNT(*) AS n FROM t WHERE t.cid = :p6"),
            ParamMisuse,
        ),
        // A Text param typed on a key column.
        (
            format!("SELECT COUNT(*) AS n {J} AND c.id = :p7"),
            ParamType,
        ),
        // Inside MIN/MAX/SUM/AVG/COUNT(col), directly or through a CTE.
        (format!("SELECT MIN(c.id) AS m {J}"), ConstructNotAllowed),
        (
            format!("SELECT MAX(i.customer_id) AS m {J}"),
            ConstructNotAllowed,
        ),
        (
            "SELECT SUM(i.id) AS s FROM invoices i".to_string(),
            ConstructNotAllowed,
        ),
        (
            "SELECT AVG(DISTINCT p.invoice_id) AS s FROM payments p".to_string(),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(i.customer_id) AS k {J}"),
            ConstructNotAllowed,
        ),
        (
            format!("{cte} SELECT MAX(t.cid) AS m FROM t"),
            ConstructNotAllowed,
        ),
        (
            format!("SELECT COUNT(*) AS n {J} HAVING SUM(i.id) > 2"),
            ConstructNotAllowed,
        ),
        // ORDER BY is not a structural place either.
        (
            "SELECT i.id, i.amount FROM invoices i ORDER BY i.id LIMIT 3".to_string(),
            ConstructNotAllowed,
        ),
    ] {
        assert_eq!(refused(&sql), want, "{sql}");
    }
    // The structural places stay open.
    for sql in [
        format!("SELECT COUNT(DISTINCT i.customer_id) AS k, COUNT(DISTINCT i.id) AS m {J}"),
        "SELECT c.id, c.segment, SUM(i.amount) AS total FROM invoices i JOIN customers c \
         ON c.id = i.customer_id GROUP BY c.id, c.segment ORDER BY total DESC LIMIT 10"
            .to_string(),
        format!(
            "{cte} SELECT COUNT(*) AS n FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1"
        ),
        format!("{cte} SELECT COUNT(DISTINCT t.cid) AS n FROM t"),
        "SELECT i.id, i.amount FROM invoices i WHERE i.amount > :p2".to_string(),
    ] {
        prepares(&ok(&sql).sql);
    }
}

#[test]
fn no_offset_and_limit_at_least_one() {
    // G2: OFFSET or LIMIT 0 give zero rows for an existing entity.
    for tail in [
        "LIMIT 1 OFFSET 1",
        "LIMIT 0",
        "LIMIT 00",
        "LIMIT 1, 1",
        "LIMIT 5 OFFSET 0",
    ] {
        let sql = format!("SELECT COUNT(*) AS n {J} {tail}");
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    for tail in ["LIMIT 1", "LIMIT 10"] {
        prepares(&ok(&format!("SELECT COUNT(*) AS n {J} {tail}")).sql);
    }
}

#[test]
fn no_constant_differences() {
    // G3: duplicate output expressions in one block, and `-` / `/` whose
    // sides are the same multiset of `+`-joined aggregates.
    for sql in [
        "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s, SUM(i.amount) AS s2 \
         FROM invoices i GROUP BY i.customer_id) \
         SELECT SUM(t.s) - SUM(t.s2) AS z FROM customers c JOIN t ON t.cid = c.id \
         WHERE c.id = :p1",
        "SELECT SUM(i.amount) AS a, SUM(i.amount) AS b FROM invoices i",
        "SELECT i.status, i.status AS s2 FROM invoices i",
        "SELECT (SUM(i.amount) + MAX(i.amount)) - (MAX(i.amount) + SUM(i.amount)) AS z \
         FROM invoices i",
        "SELECT (SUM(i.amount) + MAX(i.amount)) / (MAX(i.amount) + SUM(i.amount)) AS z \
         FROM invoices i",
        // Two operators (ruling C-CAP).
        "SELECT (SUM(i.amount) + MAX(i.amount)) - MIN(i.amount) AS z FROM invoices i",
        "SELECT SUM(i.amount) + COUNT(*) + MAX(i.amount) - (MAX(i.amount) + (COUNT(*) + \
         SUM(i.amount))) AS z FROM invoices i",
    ] {
        assert_eq!(refused(sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    prepares(&ok("SELECT SUM(i.amount) AS s, MAX(i.amount) AS m FROM invoices i").sql);
}

/// Two per-customer CTEs over different tables (or the same body twice).
fn two_ctes(a: &str, b: &str, outer: &str) -> String {
    format!(
        "WITH a AS (SELECT {a}), b AS (SELECT {b}) \
         SELECT {outer} FROM customers c JOIN a ON a.cid = c.id JOIN b ON b.cid = c.id \
         WHERE c.id = :p1"
    )
}

const INV: &str = "i.customer_id AS cid, SUM(i.amount) AS s FROM invoices i GROUP BY i.customer_id";
const PAY: &str = "p.customer_id AS cid, SUM(p.amount) AS s FROM payments p GROUP BY p.customer_id";

#[test]
fn constants_compared_by_structure() {
    // Round 5 (H1/H2/I1/M1): expressions are compared by a structural
    // fingerprint (aggregate kind, DISTINCT, column origin through CTEs),
    // never by rendered text. One rule: no fingerprint twice in one
    // arithmetic tree; no two outputs of a block with one fingerprint.
    let inv2 = "j.customer_id AS cid, sum(j.amount) AS s FROM invoices j GROUP BY j.customer_id";
    for sql in [
        // I1: case, parentheses.
        "SELECT SUM(i.amount) - sum(i.amount) AS z FROM invoices i".to_string(),
        "SELECT SUM(i.amount) - SUM((i.amount)) AS z FROM invoices i".to_string(),
        "SELECT SUM(i.amount) / Sum(i.amount) AS z FROM invoices i".to_string(),
        "SELECT ((SUM(i.amount))) - (sum(((i.amount)))) AS z FROM invoices i".to_string(),
        "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s, sum(i.amount) AS s2 \
         FROM invoices i GROUP BY i.customer_id) \
         SELECT SUM(t.s) - SUM(t.s2) AS z FROM customers c JOIN t ON t.cid = c.id \
         WHERE c.id = :p1"
            .to_string(),
        // H1: reordered leaves.
        "SELECT SUM(i.amount) + MAX(i.amount) - MAX(i.amount) - SUM(i.amount) AS z \
         FROM invoices i"
            .to_string(),
        // M1: any fingerprint twice in one arithmetic tree.
        "SELECT SUM(i.amount) - MAX(i.amount) - SUM(i.amount) + MAX(i.amount) AS z \
         FROM invoices i"
            .to_string(),
        "SELECT (SUM(i.amount) * MAX(i.amount)) - (MAX(i.amount) * SUM(i.amount)) AS z \
         FROM invoices i"
            .to_string(),
        "SELECT (SUM(i.amount) + MAX(i.amount)) - (MAX(i.amount) + MIN(i.amount)) AS z \
         FROM invoices i"
            .to_string(),
        // MIN/MAX DISTINCT is meaningless.
        "SELECT MIN(DISTINCT i.amount) AS m FROM invoices i".to_string(),
        "SELECT MAX(DISTINCT i.amount) AS m FROM invoices i".to_string(),
        // H2: duplicate outputs, in a block and through a CTE.
        "SELECT SUM(i.amount) AS a, sum((i.amount)) AS b FROM invoices i".to_string(),
        "SELECT i.status, (i.status) AS s2 FROM invoices i".to_string(),
        "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s FROM invoices i \
         GROUP BY i.customer_id) \
         SELECT SUM(t.s) AS a, sum(t.s) AS b FROM customers c JOIN t ON t.cid = c.id \
         WHERE c.id = :p1"
            .to_string(),
        // Two CTEs with the same body: the same fingerprint through origin.
        two_ctes(INV, inv2, "SUM(a.s) - SUM(b.s) AS z"),
        two_ctes(INV, inv2, "SUM(a.s) / SUM(b.s) AS z"),
        two_ctes(INV, inv2, "SUM(a.s) AS x, SUM(b.s) AS y"),
        // Ruling C-CAP: no arithmetic over CTE columns, even of different
        // origins.
        two_ctes(INV, PAY, "SUM(a.s) / SUM(b.s) AS r"),
        two_ctes(INV, PAY, "SUM(a.s) - SUM(b.s) AS d"),
    ] {
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    // Allowed: two outputs of different origins; DISTINCT is part of the fingerprint
    // (SUM(DISTINCT x) / SUM(x) is not a constant: it varies with repeats).
    for sql in [
        two_ctes(INV, PAY, "SUM(a.s) AS x, SUM(b.s) AS y"),
        "SELECT SUM(DISTINCT i.amount) / SUM(i.amount) AS r FROM invoices i".to_string(),
        "SELECT MAX(i.amount) - MIN(i.amount) AS w, SUM(i.amount) / COUNT(*) AS m \
         FROM invoices i"
            .to_string(),
    ] {
        prepares(&ok(&sql).sql);
    }
    // The rendered SQL is canonical: aggregate names upper-case, redundant
    // parentheses gone.
    let v = ok("SELECT sum((i.amount)) AS s, (count(*)) AS n FROM invoices i");
    assert!(v.sql.contains("SUM(\"_p_i\".\"amount\")"), "{}", v.sql);
    assert!(v.sql.contains("COUNT(*)"), "{}", v.sql);
    assert!(!v.sql.contains("(("), "{}", v.sql);
    prepares(&v.sql);
    let v = ok("SELECT (SUM(i.amount)) - (MAX((i.amount))) AS z FROM invoices i");
    assert!(!v.sql.contains("(("), "{}", v.sql);
    assert!(
        v.sql.contains("SUM(\"_p_i\".\"amount\") - MAX("),
        "{}",
        v.sql
    );
}

#[test]
fn count_distinct_key_only_as_outer_output() {
    // M2: COUNT(DISTINCT key/FK) only as an outermost output item.
    let k = "FROM customers c JOIN invoices i ON i.customer_id = c.id WHERE c.id = :p1";
    for sql in [
        format!("SELECT COUNT(DISTINCT c.id) - COUNT(DISTINCT i.customer_id) AS z {k}"),
        format!("SELECT COUNT(*) - COUNT(DISTINCT i.id) AS z {k}"),
        format!("SELECT COUNT(*) AS n {k} HAVING COUNT(DISTINCT i.id) > 1"),
        format!("SELECT COUNT(DISTINCT i.id) AS m {k} HAVING m > 1"),
        "WITH t AS (SELECT i.status AS st FROM invoices i GROUP BY i.status \
         HAVING COUNT(DISTINCT i.customer_id) = 2) SELECT t.st FROM t"
            .to_string(),
        "WITH t AS (SELECT i.status AS st, COUNT(DISTINCT i.customer_id) AS k \
         FROM invoices i GROUP BY i.status) SELECT t.st FROM t WHERE t.k = 2"
            .to_string(),
        "WITH t AS (SELECT i.status AS st, COUNT(DISTINCT i.customer_id) AS k \
         FROM invoices i GROUP BY i.status) SELECT t.st, t.k FROM t"
            .to_string(),
    ] {
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    for sql in [
        format!("SELECT COUNT(DISTINCT i.id) AS m, COUNT(*) AS n {k}"),
        "SELECT c.city, COUNT(DISTINCT c.id) AS n FROM customers c GROUP BY c.city \
         ORDER BY n DESC LIMIT 5"
            .to_string(),
    ] {
        prepares(&ok(&sql).sql);
    }
}

#[test]
fn arithmetic_is_capped() {
    // Ruling C-CAP: arithmetic only in the outermost SELECT, one operator,
    // each operand one aggregate over a base-table column (or COUNT(*)),
    // with disjoint normalised leaves (AVG(x) = {SUM(x), COUNT(*)},
    // COUNT(col) = COUNT(*)).
    let cte = "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) AS s FROM invoices i \
               GROUP BY i.customer_id)";
    let tail = "FROM customers c JOIN t ON t.cid = c.id WHERE c.id = :p1";
    for sql in [
        // Arithmetic over a CTE column.
        format!("{cte} SELECT SUM(t.s) - COUNT(*) AS z {tail}"),
        format!("{cte} SELECT SUM(t.s) / MAX(c.credit_limit) AS z {tail}"),
        // Commutative chains hidden in CTE columns (round-5 re-review).
        format!(
            "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) + MAX(i.amount) AS x, \
             MAX(i.amount) + SUM(i.amount) AS y FROM invoices i GROUP BY i.customer_id) \
             SELECT SUM(t.x) - SUM(t.y) AS z {tail}"
        ),
        // A CTE with an arithmetic output.
        "WITH t AS (SELECT i.customer_id AS cid, SUM(i.amount) - MIN(i.amount) AS d \
         FROM invoices i GROUP BY i.customer_id) SELECT t.cid FROM t"
            .to_string(),
        // Overlapping normalised leaves.
        "SELECT AVG(i.amount) / SUM(i.amount) AS z FROM invoices i".to_string(),
        "SELECT AVG(i.amount) / COUNT(i.amount) AS z FROM invoices i".to_string(),
        "SELECT AVG(i.amount) * COUNT(*) AS z FROM invoices i".to_string(),
        "SELECT COUNT(i.amount) - COUNT(*) AS z FROM invoices i".to_string(),
        "SELECT SUM(i.amount) - SUM(i.amount) AS z FROM invoices i".to_string(),
        // Two operators.
        "SELECT SUM(i.amount) + MAX(i.amount) - MIN(i.amount) AS z FROM invoices i".to_string(),
        "SELECT (SUM(i.amount) - SUM(i.discount)) / COUNT(*) AS z FROM invoices i".to_string(),
        // Duplicate outputs: commutative operands are sorted.
        "SELECT SUM(i.amount) + SUM(i.discount) AS a, SUM(i.discount) + SUM(i.amount) AS b \
         FROM invoices i"
            .to_string(),
        "SELECT SUM(i.amount) * MAX(i.discount) AS a, MAX(i.discount) * SUM(i.amount) AS b \
         FROM invoices i"
            .to_string(),
    ] {
        assert_eq!(refused(&sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    for sql in [
        "SELECT SUM(i.amount) / SUM(i.discount) AS share FROM invoices i".to_string(),
        "SELECT SUM(i.amount) - SUM(i.discount) AS net FROM invoices i".to_string(),
        "SELECT SUM(i.amount) * MAX(i.discount) AS p FROM invoices i".to_string(),
        "SELECT SUM(i.amount) + SUM(i.discount) AS a, SUM(i.amount) - SUM(i.discount) AS b, \
         SUM(i.discount) - SUM(i.amount) AS c FROM invoices i"
            .to_string(),
        format!("SELECT SUM(i.amount) / MAX(c.credit_limit) AS used {J}"),
        "SELECT MAX(i.amount) - MIN(i.amount) AS w, SUM(i.amount) / COUNT(*) AS m \
         FROM invoices i"
            .to_string(),
        "SELECT AVG(i.amount) / MAX(i.amount) AS r FROM invoices i".to_string(),
    ] {
        prepares(&ok(&sql).sql);
    }
}

// ---- plan 45 T2 fix round 2: join edges and the fan-out rule ----

/// `schema()` plus invoice_lines(id, invoice_id, qty, sku): invoice_id is the
/// C-G1 FK of `invoices.id` (invoices is declared as an entity).
fn schema_lines() -> Schema {
    use ColType::*;
    use ColumnClass::*;
    let mut s = schema();
    s.tables.push(TableInfo {
        name: "invoice_lines".into(),
        alias: None,
        rows: 20000,
        columns: vec![
            col("id", Integer, Identifier),
            col("invoice_id", Integer, Identifier),
            col("qty", Integer, Sensitive),
            col("sku", Text, Public),
        ],
    });
    s
}

#[test]
fn fan_out_over_a_declared_child_is_refused() {
    let s = schema_lines();
    // The invoice amount repeats once per line.
    let sql = "SELECT SUM(i.amount) AS s FROM invoices i \
               JOIN invoice_lines l ON l.invoice_id = i.id";
    assert_eq!(
        class_of(sql, &s, &no_entity()),
        ErrorClass::ConstructNotAllowed
    );
    // A many-to-one lookup: aggregate the child, join its parent.
    let sql = "SELECT SUM(l.qty) AS q FROM invoice_lines l \
               JOIN invoices i ON i.id = l.invoice_id";
    let v = validate(sql, &s, &public(), &no_entity()).expect("allowed");
    assert_eq!(
        v.sources,
        vec!["invoice_lines".to_string(), "invoices".to_string()]
    );
    assert_eq!(
        v.joins,
        vec![saiife_shield::sql::JoinEdge {
            joined: 1,
            key: 1,
            fk: 0,
            key_table: "invoices".into(),
            fk_table: "invoice_lines".into(),
            fan: true,
        }]
    );
    assert!(v.pinned_sources.is_empty());
}

#[test]
fn second_instance_of_a_table_is_refused() {
    let sql = "SELECT COUNT(*) AS n FROM customers a JOIN customers b ON a.id = b.id \
               WHERE a.id = :p1";
    assert!(validate(sql, &schema(), &public(), &params()).is_err());
}

#[test]
fn join_edges_and_pinned_source() {
    let v = ok(BALANCE);
    assert_eq!(
        v.sources,
        vec!["invoices".to_string(), "customers".to_string()]
    );
    assert_eq!(v.joins.len(), 1);
    assert_eq!(
        (v.joins[0].joined, v.joins[0].key, v.joins[0].fk),
        (1, 1, 0)
    );
    assert_eq!(v.joins[0].key_table, "customers");
    assert_eq!(v.joins[0].fk_table, "invoices");
    assert!(v.joins[0].fan);
    assert_eq!(v.pinned_sources, vec![1]);
}

#[test]
fn sum_and_avg_need_a_number_column() {
    // Plan 45 final review I2: SQLite sums the leading digits of a TEXT or
    // DATE value ('2026-07-01' is 2026) or gives 0.0.
    for sql in [
        "SELECT SUM(i.status) AS s FROM invoices i",
        "SELECT AVG(i.issued) AS a FROM invoices i",
        "SELECT SUM(DISTINCT c.city) AS s FROM customers c",
        "SELECT AVG(DISTINCT i.status) AS a FROM invoices i",
        // By origin through a CTE.
        "WITH t AS (SELECT i.customer_id AS cid, MAX(i.issued) AS d FROM invoices i \
         GROUP BY i.customer_id) SELECT SUM(t.d) AS s FROM t",
        // Arithmetic is between numbers only.
        "SELECT MAX(i.issued) - MIN(i.issued) AS w FROM invoices i",
        "SELECT COUNT(*) / MAX(i.status) AS w FROM invoices i",
    ] {
        assert_eq!(refused(sql), ErrorClass::ConstructNotAllowed, "{sql}");
    }
    // MIN / MAX / COUNT over TEXT and DATE stay.
    let v = ok(
        "SELECT MIN(i.issued) AS a, MAX(i.status) AS b, COUNT(i.status) AS n \
         FROM invoices i",
    );
    prepares(&v.sql);
    // A CTE count is a number.
    ok(
        "WITH t AS (SELECT i.customer_id AS cid, COUNT(*) AS n FROM invoices i \
        GROUP BY i.customer_id) SELECT AVG(t.n) AS a FROM t",
    );
}

#[test]
fn division_renders_as_real() {
    // Plan 45 final review I1 (ruling F-b): the left operand of `/` is cast
    // to REAL in the rendered SQL only.
    let v = ok("SELECT SUM(i.amount) / COUNT(*) AS m FROM invoices i");
    assert_eq!(
        v.sql,
        "SELECT CAST(SUM(\"_p_i\".\"amount\") AS REAL) / COUNT(*) AS \"m\" \
         FROM \"invoices\" \"_p_i\""
    );
    prepares(&v.sql);
    // Other operators are left alone.
    let v = ok("SELECT SUM(i.amount) - SUM(i.discount) AS d FROM invoices i");
    assert!(!v.sql.contains("CAST"), "{}", v.sql);
    // The planner's grammar still has no CAST.
    assert_eq!(
        refused("SELECT CAST(SUM(i.amount) AS REAL) / COUNT(*) AS m FROM invoices i"),
        ErrorClass::ConstructNotAllowed
    );
}
