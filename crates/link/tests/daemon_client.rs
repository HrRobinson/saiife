//! `Daemon::call` against an in-process daemon with `link.sock` on a tempdir
//! (the harness pattern of crates/daemon/tests/workspace_link.rs).
#![cfg(unix)]

mod common;

use common::{args, me, scratch, world};
use saiife_ipc::msg::{OP_WORKSPACE_HELLO, OP_WORKSPACE_SIGN};
use saiife_link::{Daemon, LinkError};
use serde_json::json;

#[tokio::test]
async fn daemon_call_roundtrip() {
    let w = world().await;
    let d = Daemon::new(w.run.clone(), me());

    let hello = d.call(OP_WORKSPACE_HELLO, args(json!({}))).await.unwrap();
    assert!(
        hello["machine_id"].as_str().is_some_and(|m| !m.is_empty()),
        "{hello:?}"
    );

    // An op link.sock does not serve is refused before its args are read.
    match d.call("policy.reload", args(json!({}))).await {
        Err(LinkError::Refused { error, .. }) => assert_eq!(error, "unknown_op"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn refusal_keeps_the_daemons_rule() {
    let w = world().await;
    let d = Daemon::new(w.run.clone(), me());
    // A hub hello that is not for this machine: bad_request with its rule.
    let r = d
        .call(
            OP_WORKSPACE_SIGN,
            args(json!({"purpose": "hub_hello", "data": "AAAA"})),
        )
        .await;
    match r {
        Err(LinkError::Refused { rule, message, .. }) => {
            assert_eq!(rule.as_deref(), Some("bad_request"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn missing_daemon_is_unreachable() {
    let tmp = scratch();
    let d = Daemon::new(tmp.path().to_path_buf(), me());
    match d.call(OP_WORKSPACE_HELLO, args(json!({}))).await {
        Err(LinkError::Unreachable(_)) => {}
        other => panic!("{other:?}"),
    }
}
