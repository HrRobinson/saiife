//! Golden corpus for `db.postgres` (opt-in — must be enabled explicitly).

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["db.postgres".to_string()]))
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_postgres_statements() {
    let e = engine();
    let deny = [
        r#"psql -c "DROP DATABASE prod""#,
        r#"psql -c "DROP SCHEMA public CASCADE""#,
        "DROP TABLE users;",
        "drop database prod;", // lower-case
        "TRUNCATE users",
        "TRUNCATE TABLE users",
        r#"psql -c "DELETE FROM users""#,
        "DELETE FROM sessions;",
        "dropdb proddb",
        "sudo dropdb proddb",
        r#"psql mydb -c "TRUNCATE TABLE events""#,
    ];
    for cmd in deny {
        assert_eq!(deny_pack(&e, cmd), "db.postgres", "for {cmd:?}");
    }
}

#[test]
fn allows_safe_postgres_statements() {
    let e = engine();
    let allow = [
        r#"psql -c "SELECT * FROM users""#,
        r#"psql -c "DELETE FROM users WHERE id = 1""#,
        r#"psql -c "UPDATE users SET active = false WHERE id = 2""#,
        r#"psql -c "INSERT INTO t VALUES (1)""#,
        "psql mydb",
        "createdb newdb",
        "pg_dump mydb > backup.sql",
        r#"psql -c "SELECT count(*) FROM orders""#,
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
