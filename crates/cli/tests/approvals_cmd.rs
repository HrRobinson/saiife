//! `saiife approvals`, `approve` and `reject` end to end (plan 11, Task 5),
//! against the in-process daemon of tests/approvals.rs (same world: the
//! real audit writer, vault, approval store and control server on temp
//! dirs). The CLI user is made an approver with a fake re-authentication
//! (`same_user = "reauth"`); `boss` (4242) and `carol` (4343) are ops-level
//! second uids. `pkttyagent` is a fake script (`SAIIFE_TEST_PKTTYAGENT`).
//!
//! An approval needs a second uid (`same_user = "deny"`), and the tests run
//! as one user. So the daemon is an in-process context (the real audit
//! writer, vault, approval store, control server and HTTP gateway on temp
//! dirs) served on a Unix socket to the real `saiife` binary, and the
//! approver is a fake `PeerCred` (uid 4242, `boss`, listed in `[approval]
//! approvers`) calling `approval.decide` at the ops level. The directory is
//! a fixed passwd/group text naming the test user, `boss` and `carol`
//! (4343, not an approver); the daemon looks `boss` up by uid itself.
//! The upstream is a loopback HTTPS mock; nothing leaves 127.0.0.1.
// Debug builds only: the CLI honours SAIIFE_TEST_PKTTYAGENT only there, so a release test could start the real pkttyagent.
#![cfg(all(unix, debug_assertions))]
#![allow(dead_code)]

#[path = "common/approvals_world.rs"]
mod approvals_world;
mod common;

use approvals_world::*;

#[cfg(target_os = "linux")]
use common::daemon::wait_for;
use common::daemon::{own_uid, own_user};
use saiife_daemon::approvals::{dir_in, State};
use serde_json::{json, Value};
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------- tests

#[test]
fn list_shows_pending_masked() {
    let w = world();
    // A secret in the body is never stored for approval
    // (`masked_content`); in a parameter it is masked for display.
    let body = r#"{"amount": 5, "memo": "plain"}"#;
    let id = w.ask_with(body, &[&format!("ref={SECRET}")]);
    // The own user is the requester: it sees its own request.
    let o = w.cli("approvals", &[]);
    ok(&o);
    let out = stdout(&o);
    let line = out.lines().nth(1).unwrap_or_else(|| panic!("{out}"));
    assert!(out.lines().next().unwrap().starts_with("ID"), "{out}");
    let cols: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(cols[0], id.to_string());
    assert_eq!(cols[2], own_user());
    assert_eq!(cols[3], "connector");
    assert_eq!((cols[4], cols[5]), ("erp", "invoices.create"));
    // Asked under the base config, recorded as such.
    assert_eq!((cols[6], cols[7]), ("(env", "base)"));
    assert_eq!(cols[8], "pending");
    assert!(!out.contains(SECRET));

    // `list --json`: one array.
    let o = w.cli("approvals", &["list", "--json"]);
    ok(&o);
    let v = json_out(&o);
    let items = v.as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["id"], id);
    assert_eq!(items[0]["user"], own_user());
    assert_eq!(items[0]["type"], "connector");
    assert_eq!(items[0]["state"], "pending");
    assert!(!v.to_string().contains(SECRET));

    // A decided request leaves the pending list, stays in --all.
    assert_eq!(w.decide(BOSS, id, "reject")["ok"], true);
    let o = w.cli("approvals", &["--json"]);
    assert_eq!(json_out(&o), json!([]));
    assert!(stdout(&w.cli("approvals", &[])).contains("no pending requests"));
    let v = json_out(&w.cli("approvals", &["--all", "--json"]));
    assert_eq!(v[0]["state"], "rejected", "{v}");
    let v = json_out(&w.cli("approvals", &["list", "--all", "--json"]));
    assert_eq!(v[0]["id"], id);
}

#[test]
fn show_masks_params() {
    let w = world();
    let pad = "p".repeat(3000);
    let body = format!(r#"{{"memo": "plain", "pad": "{pad}", "zz": "tail-marker"}}"#);
    let id = w.ask_with(&body, &[&format!("ref={SECRET}")]);
    let o = w.cli("approvals", &["show", &id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("[MASKED]"), "{out}");
    assert!(out.contains(&format!("request #{id}")), "{out}");
    assert!(out.contains("erp invoices.create"), "{out}");
    assert!(out.contains("(cut; use --full)"), "{out}");
    assert!(!out.contains("tail-marker"), "{out}");
    assert!(!out.contains("WARNING"), "{out}");

    let o = w.cli("approvals", &["show", &id.to_string(), "--full"]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("tail-marker"), "{out}");
    assert!(!out.contains("(cut; use --full)"), "{out}");
    assert!(!out.contains(SECRET), "{out}");

    let o = w.cli("approvals", &["show", &id.to_string(), "--json"]);
    ok(&o);
    let v = json_out(&o);
    assert_eq!(v["id"], id);
    assert_eq!(v["body_truncated"], false);
    assert!(v["body_display"].as_str().unwrap().contains("tail-marker"));
    assert!(!v.to_string().contains(SECRET));
    assert!(v.get("request_sealed").is_none());
}

/// A command request shows the project tree its grant covers (`scope`),
/// in text and in `--json`.
#[test]
fn show_prints_the_scope_of_a_command_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest};
    let w = world();
    let r = w
        .ctx
        .approvals
        .as_ref()
        .unwrap()
        .create(
            NewRequest {
                uid: own_uid(),
                sid: None,
                user: own_user(),
                session: None,
                agent: "claude".into(),
                project: "/srv/shop/sub".into(),
                kind: ApprovalType::Command,
                service: None,
                operation: None,
                capability: None,
                params: Default::default(),
                input: Some("git push --force origin main".into()),
                grant_key: Some("00".repeat(32)),
                scope: Some("/srv/shop".into()),
                ask_rule: Some("core.git/push-force".into()),
                touch_class: None,
                send: Default::default(),
            },
            |_| Ok(None),
            Duration::from_secs(600),
            std::time::SystemTime::now(),
        )
        .unwrap();
    let o = w.cli("approvals", &["show", &r.id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("  scope      /srv/shop\n"), "{out}");
    assert!(out.contains("git push --force origin main"), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &r.id.to_string(), "--json"]));
    assert_eq!(v["scope"], "/srv/shop", "{v}");
    assert!(v.get("grant_key").is_none(), "{v}");
}

/// A connector request asked under an environment names it: `approvals
/// show` on its own line, the list after the operation, `--json` as
/// `env`. One with no environment shows none.
#[test]
fn show_and_list_print_the_env_of_a_connector_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest, SendDisplay};
    let w = world();
    let new = |env: Option<&str>, env_base: bool| NewRequest {
        uid: own_uid(),
        sid: None,
        user: own_user(),
        session: None,
        agent: "claude".into(),
        project: "/srv/shop".into(),
        kind: ApprovalType::Connector,
        service: Some("erp".into()),
        operation: Some("invoices.create".into()),
        capability: Some("invoices:write".into()),
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        touch_class: None,
        send: SendDisplay {
            env: env.map(str::to_string),
            env_base,
            ..Default::default()
        },
    };
    let store = w.ctx.approvals.as_ref().unwrap();
    let create = |n| {
        store
            .create(
                n,
                |_| Ok(None),
                Duration::from_secs(600),
                std::time::SystemTime::now(),
            )
            .unwrap()
    };
    let with = create(new(Some("prod"), false));
    let without = create(new(None, false));
    let base = create(new(None, true));
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&base),
        "erp invoices.create (env base)"
    );
    let out = stdout(&w.cli("approvals", &["show", &base.id.to_string()]));
    assert!(out.contains("  env        base\n"), "{out}");
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&with),
        "erp invoices.create (env prod)"
    );
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&without),
        "erp invoices.create"
    );

    let out = stdout(&w.cli("approvals", &["show", &with.id.to_string()]));
    assert!(out.contains("  env        prod\n"), "{out}");
    let out = stdout(&w.cli("approvals", &["show", &without.id.to_string()]));
    assert!(!out.contains("  env "), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &with.id.to_string(), "--json"]));
    assert_eq!(v["env"], "prod", "{v}");

    let out = stdout(&w.cli("approvals", &[]));
    let line = |id: u64| {
        out.lines()
            .find(|l| l.split_whitespace().next() == Some(&id.to_string()))
            .unwrap_or_else(|| panic!("{out}"))
            .to_string()
    };
    assert!(
        line(with.id).contains("erp invoices.create (env prod)"),
        "{out}"
    );
    assert!(!line(without.id).contains("(env"), "{out}");
    assert!(
        line(base.id).contains("erp invoices.create (env base)"),
        "{out}"
    );
}

/// An MCP gateway request (plan 17): `show` prints the server, the tool
/// and the masked arguments; the list names it `mcp:<server> <tool>`.
#[test]
fn show_prints_server_tool_and_masked_arguments_of_an_mcp_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest, SendDisplay};
    let w = world();
    let store = w.ctx.approvals.as_ref().unwrap();
    let new = |truncated: bool| NewRequest {
        uid: own_uid(),
        sid: None,
        user: own_user(),
        session: None,
        agent: "claude".into(),
        project: "/srv/shop".into(),
        kind: ApprovalType::Mcp,
        service: Some("mcp:linear".into()),
        operation: Some("create_issue".into()),
        capability: None,
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        touch_class: None,
        send: SendDisplay {
            body_display: Some("{\"team\":\"ENG\",\"title\":\"Bug\"}".into()),
            body_sha256: Some("ab".repeat(32)),
            body_truncated: truncated,
            env_base: true,
            ..Default::default()
        },
    };
    let create = |n| {
        store
            .create(
                n,
                |_| Ok(None),
                Duration::from_secs(600),
                std::time::SystemTime::now(),
            )
            .unwrap()
    };
    let r = create(new(false));
    let o = w.cli("approvals", &["show", &r.id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("  type       mcp\n"), "{out}");
    assert!(out.contains("  server     linear\n"), "{out}");
    assert!(out.contains("  tool       create_issue\n"), "{out}");
    assert!(out.contains("  env        base\n"), "{out}");
    assert!(out.contains("  arguments (masked)\n"), "{out}");
    assert!(
        out.contains("{\"team\":\"ENG\",\"title\":\"Bug\"}"),
        "{out}"
    );
    assert!(
        out.contains(&format!("  arguments sha256 {}", "ab".repeat(32))),
        "{out}"
    );
    assert!(!out.contains("WARNING"), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &r.id.to_string(), "--json"]));
    assert_eq!(v["type"], "mcp", "{v}");
    let out = stdout(&w.cli("approvals", &[]));
    assert!(out.contains("mcp:linear create_issue"), "{out}");
    // Shown cut: approving needs --accept-truncated.
    let cut = create(new(true));
    let out = stdout(&w.cli("approvals", &["show", &cut.id.to_string()]));
    assert!(
        out.contains("WARNING: the arguments are over 4 KiB"),
        "{out}"
    );
    assert!(out.contains("--accept-truncated"), "{out}");
}

#[test]
fn show_warns_when_the_full_body_was_cut() {
    let w = world();
    let id = w.ask(BODY_A);
    let file = dir_in(&w.path().join("state")).join(format!("{id}.json"));
    let mut v: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    v["body_truncated"] = json!(true);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let o = w.cli("approvals", &["show", &id.to_string(), "--full"]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("WARNING"), "{out}");
    assert!(out.contains("--accept-truncated"), "{out}");
}

#[test]
fn approve_and_reject_round_trip() {
    let w = world();
    // The own user is not a second account: boss decides at the ops level
    // as the control, the CLI as an approver whose own request it is not.
    // Here the CLI user is the approver (reauth passes), so it can decide.
    w.own_reauth(true);
    let a = w.ask(BODY_A);
    let o = w.cli("approve", &[&a.to_string(), "--note", "looks fine"]);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{a} approved")),
        "{}",
        stdout(&o)
    );
    w.wait_state(a, State::Sent);
    assert_eq!(w.m.hits().len(), 1);
    assert_eq!(w.wait_record(a, "approved")["note"], "looks fine");

    let b = w.ask(BODY_B);
    let o = w.cli("reject", &[&b.to_string(), "--note", "no"]);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{b} rejected")),
        "{}",
        stdout(&o)
    );
    assert_eq!(w.state(b), Some(State::Rejected));
    // Its own request: a withdrawal, noted as such.
    assert_eq!(
        w.wait_record(b, "rejected")["note"],
        "cancelled by requester: no"
    );
    assert_eq!(w.m.hits().len(), 1, "a rejected request is never sent");

    // Deciding again is refused with the state (exit 2).
    let o = w.cli("reject", &[&b.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("is rejected"), "{}", stderr(&o));
}

#[test]
fn refusal_prints_rule_and_exit_2() {
    let w = world();
    // Not an approver (a reject of its own request is a withdrawal).
    let id = w.ask(BODY_A);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (not_approver)"),
        "{}",
        stderr(&o)
    );
    // Re-authentication denied.
    w.own_reauth(false);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    // What is approved is printed before any prompt, and with no
    // pkttyagent (env cleared: a terminal-only session) a hint says so.
    assert!(
        stderr(&o).contains(&format!(
            "saiife: approving request #{id}: connector erp invoices.create"
        )),
        "{}",
        stderr(&o)
    );
    // pkttyagent is polkit's: never started on macOS.
    assert_eq!(
        stderr(&o).contains("no-pkttyagent is missing"),
        cfg!(target_os = "linux"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    assert!(w.m.hits().is_empty());
    // polkit was told what is approved.
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec![format!("#{id} erp invoices.create")]
    );
    // A failed prompt cools the uid down: the next try is refused at once,
    // without asking polkit again.
    w.own_reauth(true);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (reauth_cooldown)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.reauth.details.lock().unwrap().len(), 1);
    assert_eq!(w.state(id), Some(State::Pending));
    // An unknown id.
    let o = w.cli("approve", &["999"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

#[test]
fn accept_truncated_sends_the_ack() {
    let w = world();
    w.own_reauth(true);
    let id = w.ask(BODY_A);
    let file = dir_in(&w.path().join("state")).join(format!("{id}.json"));
    let mut v: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    v["body_truncated"] = json!(true);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (truncated_not_acknowledged)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    let o = w.cli("approve", &[&id.to_string(), "--accept-truncated"]);
    ok(&o);
    w.wait_state(id, State::Sent);
}

#[test]
fn daemon_unavailable_is_exit_5() {
    let w = world();
    let id = w.ask(BODY_A);
    // Stop answering on the control socket.
    fs::remove_file(w.path().join("run/saiife.sock")).unwrap();
    for (cmd, args) in [
        ("approvals", vec![]),
        ("approve", vec![id.to_string()]),
        ("reject", vec![id.to_string()]),
    ] {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = w.cli(cmd, &a);
        assert_eq!(o.status.code(), Some(5), "{cmd}: {}", stderr(&o));
    }
}

/// Linux: macOS has no polkit, so no pkttyagent.
#[cfg(target_os = "linux")]
#[test]
fn pkttyagent_started_and_stopped_for_same_uid_reauth() {
    let w = world();
    w.own_reauth(true);
    let agent = fake_agent(w.path());
    let id = w.ask(BODY_A);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    let o = cmd.output().unwrap();
    ok(&o);
    w.wait_state(id, State::Sent);

    let pid: u32 = fs::read_to_string(w.path().join("agent.pid"))
        .expect("the fake pkttyagent was started")
        .trim()
        .parse()
        .unwrap();
    let argv = fs::read_to_string(w.path().join("agent.argv")).unwrap();
    let ppid: u32 = fs::read_to_string(w.path().join("agent.ppid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // `--process <the CLI's own pid> --fallback`; the CLI was its parent.
    assert_eq!(argv.trim(), format!("--process {ppid} --fallback"));
    assert_ne!(ppid, std::process::id());
    // The CLI is gone, and so is the agent (its own child, killed through
    // its handle and reaped): no /proc entry for it.
    assert!(
        wait_for(Duration::from_secs(5), || !Path::new(&format!(
            "/proc/{pid}"
        ))
        .exists()),
        "the fake pkttyagent {pid} is still running"
    );
}

/// `lockdown off` by an approver who is not an admin needs polkit
/// re-authentication: authorized turns it off, denied keeps it on
/// (`reauth_failed`); root turns it off without one.
#[test]
fn lockdown_off_by_an_approver_needs_reauth() {
    let w = world();
    w.own_reauth(true);
    let agent = fake_agent(w.path());
    let lockdown = |args: &[&str]| {
        let mut cmd = w.cli_cmd("lockdown", args);
        cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
        cmd.output().unwrap()
    };
    ok(&lockdown(&["on", "--scope", "connectors"]));
    let o = lockdown(&["off"]);
    ok(&o);
    assert!(
        stderr(&o).contains("turning lockdown off"),
        "{}",
        stderr(&o)
    );
    assert!(w.ctx.lockdown.get().is_none());
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec!["lockdown off".to_string()]
    );
    // The CLI started its agent first (Linux: macOS has no pkttyagent).
    assert_eq!(
        w.path().join("agent.pid").exists(),
        cfg!(target_os = "linux")
    );

    ok(&lockdown(&["on", "--scope", "connectors"]));
    w.own_reauth(false);
    let o = lockdown(&["off"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    assert!(w.ctx.lockdown.get().is_some(), "still on");
    // The refusal is on record.
    let rec = w.wait_lockdown_record("reauth_failed");
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["action"], "off", "{rec}");

    // Root needs no re-authentication.
    let r = w.op(0, "lockdown.set", json!({"on": false}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(w.ctx.lockdown.get().is_none());
}

/// Narrowing an active lockdown by an approver who is not an admin needs
/// re-authentication (detail `lockdown change`): authorized narrows it,
/// denied keeps it (`reauth_failed`, recorded).
#[test]
fn lockdown_narrowing_by_an_approver_needs_reauth() {
    let w = world();
    let agent = fake_agent(w.path());
    let lockdown = |args: &[&str]| {
        let mut cmd = w.cli_cmd("lockdown", args);
        cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
        cmd.output().unwrap()
    };
    use saiife_broker::pipeline::LockScope;
    let scope = || w.ctx.lockdown.get().map(|l| l.scope);
    w.own_reauth(true);
    ok(&lockdown(&["on"]));
    ok(&lockdown(&["on", "--scope", "connectors"]));
    assert_eq!(scope(), Some(LockScope::Connectors));
    // Widening is free: no re-authentication.
    ok(&lockdown(&["on", "--scope", "all"]));
    assert_eq!(scope(), Some(LockScope::All));
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec!["lockdown change".to_string()]
    );

    w.own_reauth(false);
    let o = lockdown(&["on", "--scope", "connectors"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(scope(), Some(LockScope::All));
    let rec = w.wait_lockdown_record("reauth_failed");
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["action"], "on", "{rec}");
}

#[test]
fn pkttyagent_not_started_for_other_users_requests_or_a_desktop() {
    let w = world();
    let agent = fake_agent(w.path());
    let started = || w.path().join("agent.pid").exists();

    // A request of another user (carol): boss's decision is not the
    // CLI's business, and the own-uid rule keeps the agent away. The CLI
    // user is an approver with reauth for its own requests only.
    w.own_reauth(true);
    let carol = ops_ask_as(&w, CAROL, BODY_A);
    // Own uid is an approver, so it sees carol's request; approving it
    // needs no re-authentication (a different requester).
    let mut cmd = w.cli_cmd("approve", &[&carol.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent for another user's request");

    // Own request on a desktop session (DISPLAY set, no SSH_TTY): none.
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent)
        .env("DISPLAY", ":0");
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent on a desktop session");

    // An SSH session with a desktop variable: started.
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent)
        .env("DISPLAY", ":0")
        .env("SSH_TTY", "/dev/pts/9");
    ok(&cmd.output().unwrap());
    // Linux only: macOS has no pkttyagent.
    assert_eq!(started(), cfg!(target_os = "linux"), "no agent over ssh");

    // A rejection never prompts.
    let _ = fs::remove_file(w.path().join("agent.pid"));
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("reject", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent for a rejection");
}

/// `api.call` as `uid` at the ops level: the pending request's id.
fn ops_ask_as(w: &World, uid: u32, body: &str) -> u64 {
    use base64::Engine as _;
    let a = w.op(
        uid,
        "api.call",
        json!({"service": "erp", "operation": "invoices.create",
               "body_b64": base64::engine::general_purpose::STANDARD.encode(body)}),
    );
    a["pending"].as_u64().unwrap_or_else(|| panic!("{a}"))
}

#[test]
fn requester_sees_only_own() {
    let w = world();
    let mine = w.ask(BODY_A);
    let carols = ops_ask_as(&w, CAROL, BODY_B);
    assert_ne!(mine, carols);

    let v = json_out(&w.cli("approvals", &["--all", "--json"]));
    let ids: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![mine], "{v}");
    let o = w.cli("approvals", &["show", &carols.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("not yours"), "{}", stderr(&o));
    let o = w.cli("approve", &[&carols.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    // An approver sees both.
    let l = w.op(BOSS, "approval.list", json!({}));
    assert_eq!(l["items"].as_array().unwrap().len(), 2);
    assert_eq!(w.state(carols), Some(State::Pending));
}
