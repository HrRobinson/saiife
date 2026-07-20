//! Golden corpus for `db.mongo` (opt-in — must be enabled explicitly).
//!
//! The pack triggers on `mongo`/`mongosh`, so the destructive shapes are tested
//! as they are actually run — through the shell's `--eval`. Precision is the
//! point: reads, filtered writes, index maintenance, and a collection NAMED
//! `drop_me` must pass; only whole-database/collection destruction blocks.

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["db.mongo".to_string()]))
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_mongo_operations() {
    let e = engine();
    let deny = [
        r#"mongosh --eval "db.dropDatabase()""#,
        r#"mongo --eval "db.dropDatabase()""#,
        r#"mongosh mydb --eval "db.dropDatabase()""#,
        r#"mongosh --eval "db.users.drop()""#,
        r#"mongosh --eval "db.orders.drop( )""#, // whitespace before paren args
        r#"mongosh --eval "db.users.deleteMany({})""#,
        r#"mongosh --eval "db.users.deleteMany({ })""#,
        r#"mongosh --eval "db.users.remove({})""#,
        // sudo-wrapped
        r#"sudo mongosh --eval "db.dropDatabase()""#,
        // chained after a benign command
        r#"cd /app && mongosh --eval "db.dropDatabase()""#,
    ];
    for cmd in deny {
        assert_eq!(deny_pack(&e, cmd), "db.mongo", "for {cmd:?}");
    }
}

#[test]
fn allows_safe_mongo_operations() {
    let e = engine();
    let allow = [
        r#"mongosh --eval "db.users.find({})""#,
        r#"mongosh --eval "db.users.findOne()""#,
        r#"mongosh --eval "db.users.aggregate([{$match:{}}])""#,
        r#"mongosh --eval "db.users.countDocuments()""#,
        // filtered deletes are not whole-collection wipes
        r#"mongosh --eval "db.users.deleteMany({status:'old'})""#,
        r#"mongosh --eval "db.users.deleteOne({_id:1})""#,
        r#"mongosh --eval "db.users.remove({age:{$lt:1}})""#,
        // index maintenance touches no documents
        r#"mongosh --eval "db.users.dropIndex('x_1')""#,
        r#"mongosh --eval "db.users.dropIndexes()""#,
        // stats / admin reads
        r#"mongosh --eval "db.stats()""#,
        r#"mongosh --eval "db.getCollectionNames()""#,
        // a collection literally NAMED drop_me, read only
        r#"mongosh --eval "db.drop_me.find({})""#,
        "mongosh --version",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
