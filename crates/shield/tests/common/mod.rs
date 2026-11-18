//! Shared synthetic fixtures for the executor tests (plan 45 T3). All data is
//! built in-test.
#![allow(dead_code)]

use rusqlite::Connection;
use saiife_shield::public::PublicValues;
use saiife_shield::schema::{
    Bound, ColType, ColumnClass, ColumnInfo, EntitySpec, Param, ParamType, Schema, TableInfo,
};
use saiife_shield::sql::{validate, Validated};

fn col(name: &str, ty: ColType, class: ColumnClass) -> ColumnInfo {
    ColumnInfo {
        name: name.into(),
        ty,
        class,
        alias: None,
    }
}

/// customers(id, first_name, last_name, city, credit_limit, segment),
/// invoices(id, customer_id, amount, status, issued, discount),
/// payments(id, customer_id, invoice_id, amount, paid); entities customers
/// and invoices.
pub fn schema() -> Schema {
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
                    col("discount", Real, Sensitive),
                ],
            },
            TableInfo {
                name: "payments".into(),
                alias: None,
                rows: 3000,
                columns: vec![
                    col("id", Integer, Identifier),
                    col("customer_id", Integer, Identifier),
                    col("invoice_id", Integer, Identifier),
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
    }
}

pub fn public() -> Vec<PublicValues> {
    vec![PublicValues {
        column: "invoices.status".into(),
        passing: vec!["open".into(), "paid".into()],
        total_distinct: 3,
    }]
}

/// The bound entity parameter `p1` (a customer).
pub fn entity(key: i64) -> Param {
    entity_named("p1", key)
}

pub fn entity_named(name: &str, key: i64) -> Param {
    Param {
        name: name.into(),
        ty: ParamType::Entity {
            table: "customers".into(),
            word: "customer".into(),
        },
        bound: Some(Bound::Keys(vec![key])),
        display: format!("Customer #{key}"),
    }
}

pub fn v(sql: &str, params: &[Param]) -> Validated {
    match validate(sql, &schema(), &public(), params) {
        Ok(v) => v,
        Err(e) => panic!("{sql}: refused {e:?}"),
    }
}

pub const DDL: &str = "CREATE TABLE customers(id INTEGER, first_name TEXT, last_name TEXT, \
    city TEXT, credit_limit REAL, segment TEXT);\
    CREATE TABLE invoices(id INTEGER, customer_id INTEGER, amount REAL, status TEXT, \
    issued TEXT, discount REAL);\
    CREATE TABLE payments(id INTEGER, customer_id INTEGER, invoice_id INTEGER, \
    amount REAL, paid TEXT);";

/// Customers: 1 Soren (3 open invoices 100/200/300 + 1 paid 50, one payment),
/// 2 has invoices but no payments, 3 has no invoices, 7 has 250 open
/// invoices of 10.
pub fn fixture() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(DDL).unwrap();
    db.execute_batch(
        "INSERT INTO customers VALUES (1,'Soren','Hansen','Aarhus',5000,'a'),\
         (2,'Bo','Berg','Odense',100,'a'),(3,'Nul','Ingen','Roskilde',1,'b'),\
         (7,'Mange','Fakturaer','Aalborg',9,'a');\
         INSERT INTO invoices VALUES (1,1,100,'open','2026-01-05',0),\
         (2,1,200,'open','2026-02-05',0),(3,1,300,'open','2026-03-05',0),\
         (4,1,50,'paid','2026-03-06',0),(5,2,70,'open','2026-03-07',0);\
         INSERT INTO payments VALUES (1,1,4,50,'2026-03-10');",
    )
    .unwrap();
    db.execute_batch(
        "INSERT INTO customers VALUES (8,'Stor','Sum','Aalborg',1,'a'),(9,'Flyd','Tal','Aalborg',1,'a');\
         INSERT INTO invoices VALUES (9001,8,10000000.00,'open','2026-05-01',0),\
         (9002,8,10000000.01,'paid','2026-05-01',0),\
         (9003,9,0.1,'open','2026-05-01',0),(9004,9,0.2,'open','2026-05-02',0),\
         (9005,9,0.3,'paid','2026-05-03',0);",
    )
    .unwrap();
    for i in 0..250 {
        db.execute(
            "INSERT INTO invoices VALUES (?1, 7, 10, 'open', '2026-04-01', 0)",
            [1000 + i],
        )
        .unwrap();
    }
    db
}

/// `n` invoices spread over `n / 4` customers, for the cap tests.
pub fn heavy(db: &Connection, n: i64) {
    let tx = db.unchecked_transaction().unwrap();
    {
        let mut st = tx
            .prepare("INSERT INTO invoices VALUES (?1, ?2, ?3, 'open', '2026-04-01', 0)")
            .unwrap();
        for i in 0..n {
            st.execute(rusqlite::params![100_000 + i, 50 + i / 4, (i % 977) as f64])
                .unwrap();
        }
    }
    tx.commit().unwrap();
}
