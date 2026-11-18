//! Plan 45 Task 3 (ruling C5): `hard_heap_limit` is process-wide, so the
//! heap-cap test has its own test binary.

mod common;

use common::*;
use saiife_shield::calc::{run, Caps};
use saiife_shield::sql::ErrorClass;

#[test]
fn heap_cap() {
    let mut db = fixture();
    heavy(&db, 200_000);
    let val = v(
        "SELECT i.id, SUM(i.amount) AS s FROM invoices i GROUP BY i.id ORDER BY s DESC",
        &[],
    );
    let c = Caps {
        heap_bytes: 100_000,
        ..Caps::default()
    };
    let f = match run(&mut db, &val, &[], &[], &c) {
        Ok(rs) => panic!("expected memory_cap, got {} rows", rs.rows.len()),
        Err(f) => f,
    };
    assert_eq!(f.class, ErrorClass::MemoryCap);
    assert_eq!(f.empty_for, None);
}
