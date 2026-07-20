//! Golden corpus for `db.mysql` (opt-in — must be enabled explicitly).
//!
//! The pack triggers on `mysql`/`mysqladmin`, so the destructive statements are
//! tested as they are actually run — through the MySQL CLI. Precision is the
//! point: SELECT, a DELETE *with* a WHERE, and read/backup tools must pass.

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["db.mysql".to_string()]))
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_mysql_statements() {
    let e = engine();
    let deny = [
        r#"mysql -e "DROP DATABASE prod""#,
        r#"mysql -e "drop database prod""#, // lower-case
        r#"mysql -e "DROP SCHEMA app CASCADE""#,
        r#"mysql -e "DROP TABLE users""#,
        r#"mysql prod -e "DROP TABLE users""#,
        r#"mysql -e "TRUNCATE users""#,
        r#"mysql -e "TRUNCATE TABLE events""#,
        r#"mysql -e "TRUNCATE TABLE app.events""#, // schema-qualified identifier
        r#"mysql -e "DELETE FROM users""#,
        r#"mysql -e "DELETE FROM sessions;""#,
        r#"mysql -e "GRANT ALL PRIVILEGES ON app.* TO 'x'@'%'""#,
        "mysqladmin drop proddb",
        "mysqladmin -u root -psecret drop proddb",
        "sudo mysqladmin drop proddb",
        // sudo-wrapped SQL
        r#"sudo mysql -e "DROP DATABASE prod""#,
        // chained after a benign command
        r#"cd /app && mysql -e "DROP TABLE users""#,
    ];
    for cmd in deny {
        assert_eq!(deny_pack(&e, cmd), "db.mysql", "for {cmd:?}");
    }
}

#[test]
fn allows_safe_mysql_statements() {
    let e = engine();
    let allow = [
        r#"mysql -e "SELECT * FROM users""#,
        r#"mysql -e "SELECT count(*) FROM orders""#,
        r#"mysql -e "DELETE FROM users WHERE id = 1""#,
        r#"mysql -e "UPDATE users SET active = 0 WHERE id = 2""#,
        r#"mysql -e "INSERT INTO t VALUES (1)""#,
        r#"mysql -e "SHOW GRANTS FOR 'x'@'%'""#, // read, not GRANT ALL
        r#"mysql -e "SELECT * FROM drop_me""#,    // 'drop' only in a table name
        "mysql prod",
        "mysqldump prod > backup.sql",
        "mysqladmin status",
        "mysqladmin ping",
        "mysqladmin -u root extended-status",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
