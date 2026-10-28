//! Email connector (plan 14, Task 13): the built-in `email` manifest through
//! the whole pipeline against the loopback SMTP and IMAP mocks shared with the
//! mail transport tests (`common/mail_mock.rs`). Nothing leaves 127.0.0.1.

mod common;

use common::mail_mock::*;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{Manifest, OpKind};
use saiife_broker::pipeline::{Outcome, PolicySnapshot};
use saiife_broker::Catalog;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn snapshot(smtp: (u16, &str), imap: (u16, &str)) -> PolicySnapshot {
    snapshot_with(smtp, imap, "")
}

/// The snapshot with `extra` appended to the service table.
fn snapshot_with(smtp: (u16, &str), imap: (u16, &str), extra: &str) -> PolicySnapshot {
    snapshot_allow(
        smtp,
        imap,
        r#"["mail:write", "mail:read", "folders:read"]"#,
        extra,
    )
}

fn snapshot_allow(
    smtp: (u16, &str),
    imap: (u16, &str),
    allow: &str,
    extra: &str,
) -> PolicySnapshot {
    snapshot_for("email", smtp, imap, allow, extra)
}

/// The built-in catalog: the `email` manifest as shipped.
fn catalog() -> Catalog {
    Catalog::new(saiife_broker::manifest::builtin(), Vec::new())
}

fn email() -> &'static Manifest {
    saiife_broker::manifest::builtin()
        .iter()
        .find(|m| m.id == "email")
        .expect("email is a built-in manifest")
}

// ---------------------------------------------------------------- tests

#[test]
fn manifest_shape() {
    let m = email();
    assert_eq!(m.transport, saiife_broker::manifest::Transport::Mail);
    assert!(m.base_url.is_empty());
    assert_eq!(m.hosts, ["{smtp_host}", "{imap_host}"]);
    assert_eq!(m.auth.len(), 1);
    assert_eq!(m.auth[0].kind, "basic");
    for p in [
        "smtp_host",
        "smtp_port",
        "smtp_tls",
        "imap_host",
        "imap_port",
        "imap_tls",
        "from",
    ] {
        assert!(m.params.contains_key(p), "no service param {p}");
    }
    let want = [
        ("mail.send", "mail:write", OpKind::Write),
        ("folders.list", "folders:read", OpKind::Read),
        ("mail.list", "mail:read", OpKind::Read),
        ("mail.get", "mail:read", OpKind::Read),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind) in want {
        let op = m.operation.iter().find(|o| o.id == id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
        assert!(op.method.is_empty() && op.path.is_empty(), "{id}");
    }
}

#[tokio::test]
async fn send_and_list_end_to_end() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let (ip, _) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((sp, "implicit"), (ip, "implicit"));
    let cat = catalog();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "Weekly report")],
        Some("Hello\n"),
    );
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    assert_eq!(
        done(&o).1,
        serde_json::json!({ "sent": true, "to": "a@acme.com" })
    );
    assert_eq!(tr.capability.as_deref(), Some("mail:write:to=a@acme.com"));
    assert!(
        log.any(|l| l == "MAIL FROM:<bot@acme.com>"),
        "{:?}",
        log.lines()
    );
    assert_no_secret(&c, &snap, &tr, &o);

    let (o, tr) = go(&call("folders.list", &[], None), &snap, &cat, &up).await;
    assert_eq!(done(&o).1["folders"][0]["name"], "INBOX");
    assert_eq!(tr.capability.as_deref(), Some("folders:read"));
    let (o, tr) = go(
        &call("mail.list", &[("folder", "INBOX"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(tr.capability.as_deref(), Some("mail:read:folder=INBOX"));
    match &o {
        Outcome::Done { next, .. } => {
            let n = next.as_ref().expect("a next page");
            assert_eq!(n.get("before_uid").map(String::as_str), Some("104"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn send_only_to_allowed_domain() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_allow(
        (sp, "implicit"),
        (1, "implicit"),
        r#"["mail:read"]"#,
        "[[services.mail.rule]]\ncapability = \"mail:write\"\nwhen = { to = \"*@acme.com\" }\naction = \"allow\"",
    );
    let cat = catalog();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, _) = go(&c, &snap, &cat, &up).await;
    assert_eq!(done(&o).0, 200);
    assert_eq!(log.conns.load(Ordering::SeqCst), 1);

    for to in ["a@evil.test", "a@acme.com.evil.test", "a@sub.acme.com"] {
        let c = call("mail.send", &[("to", to), ("subject", "s")], Some("b"));
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert!(matches!(o, Outcome::Denied { .. }), "{to}: {o:?}");
    }
    assert_eq!(
        log.conns.load(Ordering::SeqCst),
        1,
        "a denied send connects nowhere"
    );
}

#[tokio::test]
async fn reads_leave_seen_flag_unset() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let cat = catalog();
    for c in [
        call("folders.list", &[], None),
        call("mail.list", &[("folder", "INBOX")], None),
        call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None),
    ] {
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(done(&o).0, 200);
    }
    let lines = log.lines();
    assert!(!log.select_seen.load(Ordering::SeqCst), "{lines:?}");
    // The mock marks a message \Seen when it is stored or fetched without PEEK.
    for uid in 101..=105 {
        assert!(!log.is_seen(uid), "uid {uid} was marked seen: {lines:?}");
    }
    // Every message read is a PEEK; nothing stores flags.
    assert!(lines.iter().any(|l| l.contains("BODY.PEEK[]")), "{lines:?}");
    assert!(
        !lines.iter().any(|l| {
            let u = l.to_ascii_uppercase();
            u.contains(" STORE ")
                || u.contains(" SELECT ")
                || u.contains("BODY[")
                || u.contains("RFC822)")
                || u.contains(" COPY ")
                || u.contains(" EXPUNGE")
        }),
        "{lines:?}"
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains(" EXAMINE ")).count(),
        2,
        "{lines:?}"
    );
}

#[tokio::test]
async fn writes_per_hour_caps_send() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_with(
        (sp, "implicit"),
        (1, "implicit"),
        "[services.mail.limits]\nwrites_per_hour = 2",
    );
    let cat = catalog();
    let lim = Limiter::new();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    for _ in 0..2 {
        let (o, _) = go_with(&c, &snap, &cat, &up, &lim).await;
        assert_eq!(done(&o).0, 200);
    }
    let (o, tr) = go_with(&c, &snap, &cat, &up, &lim).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "writes_per_hour"
            }
        ),
        "{o:?}"
    );
    assert!(!tr.sent);
    assert_eq!(log.conns.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn omitted_folder_is_inbox_for_the_policy() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot_with(
        (1, "implicit"),
        (ip, "implicit"),
        "deny = [\"mail:read:folder=INBOX\"]",
    );
    let cat = catalog();
    for c in [
        call("mail.list", &[], None),
        call("mail.get", &[("uid", "104")], None),
        call("mail.list", &[("folder", "INBOX")], None),
    ] {
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert!(matches!(o, Outcome::Denied { .. }), "{:?}: {o:?}", c.params);
    }
    assert_eq!(
        log.conns.load(Ordering::SeqCst),
        0,
        "a denied read connects nowhere"
    );
    // Another folder is not caught by the rule.
    let c = call("mail.list", &[("folder", "Sent")], None);
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    assert!(!matches!(o, Outcome::Denied { .. }), "{o:?}");
    assert_eq!(tr.capability.as_deref(), Some("mail:read:folder=Sent"));
    // Without a rule the omitted folder reads INBOX and says so.
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let (o, tr) = go(&call("mail.list", &[], None), &snap, &cat, &up).await;
    assert_eq!(done(&o).1["folder"], "INBOX");
    assert_eq!(tr.capability.as_deref(), Some("mail:read:folder=INBOX"));
}

const ACME_RULE: &str =
    "[[services.mail.rule]]\ncapability = \"mail:write\"\nwhen = { to = \"*@acme.com\" }\naction = \"allow\"";

#[tokio::test]
async fn strict_recipient_and_lowercased_domain() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_allow(
        (sp, "implicit"),
        (1, "implicit"),
        r#"["mail:read"]"#,
        ACME_RULE,
    );
    let cat = catalog();
    let send = |to: &str| call("mail.send", &[("to", to), ("subject", "s")], Some("b"));

    // The domain is lower-cased before the rule looks, and when sending.
    let (o, tr) = go(&send("A@ACME.COM"), &snap, &cat, &up).await;
    assert_eq!(done(&o).0, 200);
    assert_eq!(tr.capability.as_deref(), Some("mail:write:to=A@acme.com"));
    assert!(
        log.any(|l| l == "RCPT TO:<A@acme.com>"),
        "{:?}",
        log.lines()
    );

    for to in [
        "a@acme.com.",
        "a@-acme.com",
        "a@acme-.com",
        "a@acme..com",
        "user%evil.com@acme.com",
        "evil.com!a@acme.com",
    ] {
        let (o, _) = go(&send(to), &snap, &cat, &up).await;
        assert!(matches!(o, Outcome::Denied { .. }), "{to}: {o:?}");
    }
    assert_eq!(log.conns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_matching_recipient_goes_to_approval_under_ask() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_allow(
        (sp, "implicit"),
        (1, "implicit"),
        r#"["mail:read"]"#,
        &format!("ask = [\"mail:write\"]\n{ACME_RULE}"),
    );
    let cat = catalog();
    let send = |to: &str| call("mail.send", &[("to", to), ("subject", "s")], Some("b"));
    let (o, _) = go(&send("a@evil.test"), &snap, &cat, &up).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    // `ask` is the stricter verdict: an allow rule does not loosen it.
    let (o, _) = go(&send("a@Acme.Com"), &snap, &cat, &up).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    assert_eq!(
        log.conns.load(Ordering::SeqCst),
        0,
        "nothing is sent before approval"
    );
}
