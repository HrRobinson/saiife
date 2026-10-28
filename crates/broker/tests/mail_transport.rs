//! The mail transport (plan 14, Task 6): `mail.send` over SMTP and the
//! read-only IMAP operations, through the whole pipeline, against loopback
//! SMTP and IMAP mock servers with rcgen certificates, scripted line by
//! line. Nothing leaves 127.0.0.1.

mod common;

use base64::Engine as _;
use common::mail_mock::*;
use saiife_broker::manifest::Manifest;
use saiife_broker::pipeline::{OpRef, Outcome, PolicySnapshot};
use saiife_broker::Catalog;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const MANIFEST: &str = r#"
id = "test-mail"
version = 1
title = "Test mail"
hosts = ["{smtp_host}", "{imap_host}"]
transport = "mail"
auth = [{ kind = "basic" }]

[params.smtp_host]
type = "string"
pattern = '^[a-z0-9.-]+$'
required = true

[params.smtp_port]
type = "int:1..65535"

[params.smtp_tls]
type = "enum:implicit,starttls"

[params.imap_host]
type = "string"
pattern = '^[a-z0-9.-]+$'
required = true

[params.imap_port]
type = "int:1..65535"

[params.imap_tls]
type = "enum:implicit,starttls"

[params.from]
type = "string"
required = true

[[operation]]
id = "mail.send"
capability = "mail:write"
qualifier = "to={to}"
kind = "write"
body = "text"
query = { to = 'string:[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}', subject = "string:.{1,998}" }

[[operation]]
id = "folders.list"
capability = "folders:read"
kind = "read"

[[operation]]
id = "mail.list"
capability = "mail:read"
qualifier = "folder={folder}"
kind = "read"
query = { folder = "string", since = "datetime", unseen = "bool", limit = "int:1..100", before_uid = "int" }
pagination = { cursor = { param = "before_uid", next = "next_before_uid" } }

[[operation]]
id = "mail.get"
capability = "mail:read"
qualifier = "folder={folder}"
kind = "read"
query = { folder = "string", uid = "int" }
"#;

fn snapshot(smtp: (u16, &str), imap: (u16, &str)) -> PolicySnapshot {
    snapshot_for(
        "test-mail",
        smtp,
        imap,
        r#"["mail:write", "mail:read", "folders:read"]"#,
        "",
    )
}

fn catalog_of(text: &str) -> Catalog {
    Catalog::new(&[], vec![Manifest::parse(text).unwrap()])
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn smtp_send_one_recipient_golden_transcript() {
    let p = pki();
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "Weekly report")],
        Some("Hello,\n.this line starts with a dot\nGrüße = regards \n"),
    );
    let (o, tr) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v, serde_json::json!({ "sent": true, "to": "a@acme.com" }));
    assert_eq!(tr.capability.as_deref(), Some("mail:write:to=a@acme.com"));
    assert_no_secret(&c, &snap, &tr, &o);

    // The transcript, with the login, the date and the message id normalized.
    let lines = log.lines();
    assert!(lines.contains(&format!("AUTH PLAIN {}", auth_b64())));
    let got: String = lines
        .iter()
        .map(|l| {
            if l.starts_with("AUTH PLAIN ") {
                "AUTH PLAIN [login]".to_string()
            } else if l.starts_with("Date: ") {
                "Date: [date]".to_string()
            } else if l.starts_with("Message-ID: ") {
                assert!(l.ends_with(".saiife@acme.com>"), "{l}");
                "Message-ID: [id]".to_string()
            } else {
                l.clone()
            }
        })
        .map(|l| l + "\n")
        .collect();
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/mail_send.smtp"
    ))
    .unwrap();
    assert_eq!(got, golden);
    assert_eq!(lines.iter().filter(|l| l.starts_with("RCPT")).count(), 1);
}

#[tokio::test]
async fn smtp_starttls_then_send() {
    let p = pki();
    let (sp, log) = smtp_server(&p, Smtp::StartTls).await;
    let snap = snapshot((sp, "starttls"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 200);
    let lines = log.lines();
    assert_eq!(&lines[..3], ["EHLO saiife", "STARTTLS", "EHLO saiife"]);
}

#[tokio::test]
async fn starttls_missing_refused_before_auth() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    // SMTP.
    let (sp, log) = smtp_server(&p, Smtp::NoStartTls).await;
    let snap = snapshot((sp, "starttls"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, tr) = go(&c, &snap, &catalog_of(MANIFEST), &up).await;
    assert!(failed(&o).contains("STARTTLS"), "{o:?}");
    assert_eq!(log.lines(), ["EHLO saiife"]);
    assert_no_secret(&c, &snap, &tr, &o);
    // IMAP.
    let (ip, log) = imap_server(&p, Imap::NoStartTls).await;
    let snap = snapshot((1, "implicit"), (ip, "starttls"));
    let c = call("folders.list", &[], None);
    let (o, tr) = go(&c, &snap, &catalog_of(MANIFEST), &up).await;
    assert!(failed(&o).contains("STARTTLS"), "{o:?}");
    assert!(
        !log.any(|l| {
            let u = l.to_ascii_uppercase();
            u.contains("AUTHENTICATE") || u.contains("LOGIN")
        }),
        "{:?}",
        log.lines()
    );
    assert_no_secret(&c, &snap, &tr, &o);
}

#[tokio::test]
async fn imap_starttls_two_step_authenticate() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::StartTls).await;
    let snap = snapshot((1, "implicit"), (ip, "starttls"));
    let c = call("folders.list", &[], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v["folders"][1]["name"], "Sent");
    assert_eq!(v["folders"][1]["attributes"][1], "\\Sent");
    let lines = log.lines();
    // The plaintext capabilities are asked again after TLS.
    assert_eq!(lines[0], "s1 CAPABILITY");
    assert_eq!(lines[1], "s2 STARTTLS");
    assert_eq!(lines[2], "s3 CAPABILITY");
    assert_eq!(lines[3], "s4 AUTHENTICATE PLAIN");
    assert_eq!(lines[4], auth_b64());
}

#[tokio::test]
async fn crlf_in_subject_rejected() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let cat = catalog_of(MANIFEST);
    for params in [
        [("to", "a@acme.com"), ("subject", "hi\r\nBcc: b@evil.test")],
        [("to", "a@acme.com"), ("subject", "hi\nBcc: b@evil.test")],
        [("to", "a@acme.com\r\nBcc: b@evil.test"), ("subject", "hi")],
        [("to", "a@acme.com,b@evil.test"), ("subject", "hi")],
    ] {
        let (o, _) = go(&call("mail.send", &params, Some("b")), &snap, &cat, &up).await;
        assert_eq!(rule(&o), "bad_param", "{params:?}");
    }
    // A manifest with loose types: the transport still refuses before
    // connecting.
    let loose = MANIFEST.replace(
        r#"query = { to = 'string:[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}', subject = "string:.{1,998}" }"#,
        r#"query = { to = "string", subject = "string" }"#,
    );
    assert_ne!(loose, MANIFEST);
    let cat = catalog_of(&loose);
    for to in [
        "a@acme.com,b@evil.test",
        "a@acme.com b@evil.test",
        "<a@acme.com>",
    ] {
        let (o, _) = go(
            &call("mail.send", &[("to", to), ("subject", "hi")], Some("b")),
            &snap,
            &cat,
            &up,
        )
        .await;
        assert_eq!(rule(&o), "bad_param", "{to}");
    }
    assert_eq!(log.conns.load(Ordering::SeqCst), 0, "nothing may connect");
}

#[tokio::test]
async fn examine_never_select() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    for c in [
        call("mail.list", &[("folder", "INBOX")], None),
        call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None),
    ] {
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(done(&o).0, 200);
    }
    assert!(!log.select_seen.load(Ordering::SeqCst), "{:?}", log.lines());
    assert_eq!(
        log.lines()
            .iter()
            .filter(|l| l.contains("EXAMINE \"INBOX\""))
            .count(),
        2
    );
}

#[tokio::test]
async fn fetch_uses_body_peek() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 200);
    let fetches: Vec<String> = log
        .lines()
        .into_iter()
        .filter(|l| l.contains("FETCH"))
        .collect();
    assert_eq!(fetches.len(), 1);
    assert!(
        fetches[0].ends_with("UID FETCH 104 (UID BODY.PEEK[])"),
        "{fetches:?}"
    );
    assert!(!log.any(|l| l.contains("BODY[") || l.contains("RFC822)") || l.contains("STORE")));
}

#[tokio::test]
async fn missing_uid_is_404() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "999")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 404);
}

#[tokio::test]
async fn literal_over_limit_refused() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::HugeLiteral).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let started = Instant::now();
    let (o, tr) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(20)),
    )
    .await;
    let r = failed(&o);
    assert!(
        r.contains("2147483648") && r.contains("over the read limit"),
        "{r}"
    );
    // Refused from the announced size, not after reading or a timeout.
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(tr.sent);
}

#[tokio::test]
async fn endless_line_times_out_or_cuts() {
    let p = pki();
    let cat = catalog_of(MANIFEST);
    // A line that never ends is cut at 8 KiB.
    let (ip, _log) = imap_server(&p, Imap::EndlessLine).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let started = Instant::now();
    let (o, _) = go(
        &call("folders.list", &[], None),
        &snap,
        &cat,
        &upstream(&p, Duration::from_secs(20)),
    )
    .await;
    assert!(failed(&o).contains("line too long"), "{o:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // A server that says nothing runs into the timeout.
    let (ip, _log) = imap_server(&p, Imap::Silent).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let started = Instant::now();
    let (o, _) = go(
        &call("folders.list", &[], None),
        &snap,
        &cat,
        &upstream(&p, Duration::from_millis(800)),
    )
    .await;
    assert!(failed(&o).contains("timeout"), "{o:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn mail_list_next_before_uid() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    let page = |o: &Outcome| -> (Vec<u64>, Option<BTreeMap<String, String>>) {
        match o {
            Outcome::Done { finished, next } => {
                let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
                let uids = v["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m["uid"].as_u64().unwrap())
                    .collect();
                (uids, next.clone())
            }
            other => panic!("{other:?}"),
        }
    };
    let (o, _) = go(
        &call("mail.list", &[("folder", "INBOX"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [105, 104]);
    let next = next.expect("a next page");
    assert_eq!(next.get("before_uid").map(String::as_str), Some("104"));
    // The first message carries its envelope.
    if let Outcome::Done { finished, .. } = &o {
        let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
        let m = &v["messages"][0];
        assert_eq!(m["subject"], "Report 105");
        assert_eq!(m["from"][0]["address"], "alice@acme.com");
        assert_eq!(m["to"][0]["name"], "Bob");
        assert_eq!(m["size"], 1105);
        assert_eq!(m["flags"][0], "\\Seen");
        assert_eq!(m["date"], "2026-03-02T10:00:00Z");
    }
    let p2: Vec<(&str, &str)> = next.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (o, _) = go(&call("mail.list", &p2, None), &snap, &cat, &up).await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [103, 102]);
    let next = next.expect("a next page");
    assert_eq!(next.get("before_uid").map(String::as_str), Some("102"));
    let p3: Vec<(&str, &str)> = next.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (o, _) = go(&call("mail.list", &p3, None), &snap, &cat, &up).await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [101]);
    assert!(next.is_none());
    assert!(
        log.any(|l| l.ends_with("UID SEARCH UID 1:103")),
        "{:?}",
        log.lines()
    );
    assert!(log.any(|l| l.ends_with("UID FETCH 105,104 (UID FLAGS RFC822.SIZE ENVELOPE)")));
}

#[tokio::test]
async fn message_json_text_html_attachments_meta() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v["uid"], 104);
    assert_eq!(
        v["from"],
        serde_json::json!([{ "name": "Alice", "address": "alice@acme.com" }])
    );
    assert_eq!(v["to"][0]["address"], "bob@acme.com");
    assert_eq!(v["cc"][0]["address"], "carol@acme.com");
    assert_eq!(v["subject"], "Quartalsbericht Übersicht");
    assert_eq!(v["date"], "2026-03-02T10:00:00Z");
    assert_eq!(
        v["text"].as_str().unwrap().trim(),
        "Hello Bob, the report is attached."
    );
    assert!(v["html"].as_str().unwrap().contains("<b>report</b>"));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(ATTACHMENT_B64)
        .unwrap();
    assert_eq!(
        v["attachments"],
        serde_json::json!([{ "name": "report.pdf", "type": "application/pdf", "size": decoded.len() }])
    );
    // No attachment content, in either form.
    let body = match &o {
        Outcome::Done { finished, .. } => String::from_utf8_lossy(&finished.body).into_owned(),
        _ => unreachable!(),
    };
    assert!(!body.contains(ATTACHMENT_B64));
    assert!(!body.contains("saiife-attachment-body"));
}

#[tokio::test]
async fn password_never_in_error_or_record() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    // An IMAP server that echoes the login on a refusal.
    let (ip, _log) = imap_server(&p, Imap::EchoPassword).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("folders.list", &[], None);
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    assert_eq!(failed(&o), "upstream: AUTHENTICATE: refused");
    assert_no_secret(&c, &snap, &tr, &o);
    // An SMTP server that puts the password in a reply that is shown.
    let (sp, _log) = smtp_server(&p, Smtp::EchoPassword).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    let r = failed(&o);
    assert!(r.contains("550") && r.contains("[MASKED]"), "{r}");
    assert!(r.len() <= 200);
    assert_no_secret(&c, &snap, &tr, &o);
}

#[tokio::test]
async fn mail_proxy_path_unknown_operation() {
    let p = pki();
    let (sp, slog) = smtp_server(&p, Smtp::Implicit).await;
    let (ip, ilog) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((sp, "implicit"), (ip, "implicit"));
    let cat = catalog_of(MANIFEST);
    let up = upstream(&p, Duration::from_secs(5));
    for (method, path) in [
        ("POST", "/mail.send"),
        ("GET", "/folders.list"),
        ("GET", "/"),
    ] {
        let mut c = call("x", &[], None);
        c.op = OpRef::Proxy {
            method: method.into(),
            path: path.into(),
        };
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(rule(&o), "unknown_operation", "{method} {path}");
    }
    assert_eq!(slog.conns.load(Ordering::SeqCst), 0);
    assert_eq!(ilog.conns.load(Ordering::SeqCst), 0);
}

#[test]
fn mail_manifest_shape() {
    assert!(Manifest::parse(MANIFEST).is_ok());
    let bad = [
        // A base_url.
        MANIFEST.replace(
            "transport = \"mail\"",
            "transport = \"mail\"\nbase_url = \"https://x.test\"",
        ),
        // Other hosts.
        MANIFEST.replace(
            "hosts = [\"{smtp_host}\", \"{imap_host}\"]",
            "hosts = [\"{smtp_host}\"]",
        ),
        // A method or path on an operation.
        MANIFEST.replace(
            "id = \"folders.list\"",
            "id = \"folders.list\"\nmethod = \"GET\"\npath = \"/f\"",
        ),
        // An operation that is not one of the four.
        MANIFEST.replace("id = \"folders.list\"", "id = \"mail.delete\""),
        // A write without a text body, a read with one.
        MANIFEST.replace("body = \"text\"", ""),
        MANIFEST.replace(
            "id = \"folders.list\"\ncapability = \"folders:read\"",
            "id = \"folders.list\"\nbody = \"text\"\ncapability = \"folders:read\"",
        ),
        // An auth other than basic.
        MANIFEST.replace(
            "auth = [{ kind = \"basic\" }]",
            "auth = [{ kind = \"bearer\", secret_field = \"token\" }]",
        ),
        // A host param without an anchored pattern.
        MANIFEST.replacen("pattern = '^[a-z0-9.-]+$'\n", "", 1),
        // Fixed headers.
        MANIFEST.replace(
            "transport = \"mail\"",
            "transport = \"mail\"\nheaders = { X = \"y\" }",
        ),
    ];
    for (i, text) in bad.iter().enumerate() {
        assert_ne!(text, MANIFEST, "case {i} did not change the manifest");
        assert!(Manifest::parse(text).is_err(), "case {i} parsed");
    }
}

#[test]
fn host_params_must_be_bare_hostnames() {
    let cat = catalog_of(MANIFEST);
    let mut snap = snapshot((1, "implicit"), (1, "implicit"));
    assert!(saiife_broker::catalog::validate(&snap.config, &cat).is_ok());
    let svc = snap.config.services.get_mut("mail").unwrap();
    svc.params.insert("imap_host".into(), "127.0.0.1".into());
    assert!(saiife_broker::catalog::validate(&snap.config, &cat).is_err());
}

#[test]
fn deep_bodystructure_refused_on_a_small_stack() {
    // 2 MiB, the stack of a tokio worker thread in the daemon (and set
    // explicitly, whatever RUST_MIN_STACK says). Without the depth guard
    // imap-proto's recursion over 1000 parentheses overflows it and aborts
    // the process (checked by hand); a smaller stack does not fit the
    // unoptimized pipeline itself.
    let h = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(Box::pin(async {
                let p = pki();
                let (ip, _log) = imap_server(&p, Imap::DeepNest).await;
                let snap = snapshot((1, "implicit"), (ip, "implicit"));
                let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
                let (o, tr) = Box::pin(go(
                    &c,
                    &snap,
                    &catalog_of(MANIFEST),
                    &upstream(&p, Duration::from_secs(5)),
                ))
                .await;
                let r = failed(&o).to_string();
                assert!(r.contains("nested too deep"), "{r}");
                assert!(!r.contains("BODYSTRUCTURE"), "no server text: {r}");
                assert_no_secret(&c, &snap, &tr, &o);
            }));
        })
        .unwrap();
    h.join().expect("the call fails cleanly");
}

#[tokio::test]
async fn mail_list_windows_over_5000_uids() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Big).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(10));
    let cat = catalog_of(MANIFEST);
    let page = |o: &Outcome| -> (Vec<u64>, Option<String>) {
        let (status, v) = done(o);
        assert_eq!(status, 200);
        let uids = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["uid"].as_u64().unwrap())
            .collect();
        let next = match o {
            Outcome::Done { next, .. } => next.as_ref().and_then(|n| n.get("before_uid").cloned()),
            _ => None,
        };
        (uids, next)
    };
    let searches = |log: &Log| -> Vec<String> {
        log.lines()
            .into_iter()
            .filter(|l| l.contains("UID SEARCH"))
            .collect()
    };
    // The newest page: one window.
    let (o, _) = go(
        &call("mail.list", &[("limit", "3")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![5000, 4999, 4998], Some("4998".into())));
    assert_eq!(searches(&log).len(), 1);
    assert!(
        searches(&log)[0].ends_with("UID SEARCH UID 4501:5000"),
        "{:?}",
        searches(&log)
    );
    // Unseen: windows down to UID 1 until two hits are found.
    let (o, _) = go(
        &call("mail.list", &[("unseen", "true"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![4990, 7], Some("7".into())));
    let s = searches(&log);
    assert_eq!(s.len(), 1 + 10, "{s:?}");
    assert!(
        s.last().unwrap().ends_with("UID SEARCH UID 1:500 UNSEEN"),
        "{s:?}"
    );
    for l in &s {
        let range = l.split(' ').nth(4).unwrap();
        let (a, b) = range.split_once(':').unwrap();
        let (a, b): (u32, u32) = (a.parse().unwrap(), b.parse().unwrap());
        assert!(b >= a && b - a < 500, "{l}");
    }
    // The page below 7: the last unseen one, and no next page.
    let (o, _) = go(
        &call(
            "mail.list",
            &[("unseen", "true"), ("limit", "2"), ("before_uid", "7")],
            None,
        ),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![3], None));
    // The UIDNEXT fallback was used, never a search of the whole folder.
    assert!(log.any(|l| l.ends_with("FETCH * (UID)")));
    assert!(!log.any(|l| l.ends_with("UID SEARCH ALL") || l.ends_with("UID SEARCH UNSEEN")));
}

#[tokio::test]
async fn mail_get_is_cut_to_max_response_bytes() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let mut snap = snapshot((1, "implicit"), (ip, "implicit"));
    let max = 400;
    snap.config
        .services
        .get_mut("mail")
        .unwrap()
        .limits
        .max_response_bytes = Some(max);
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    match &o {
        Outcome::Done { finished, .. } => {
            assert!(
                finished.body.len() <= max as usize,
                "{}",
                finished.body.len()
            );
            assert!(!finished.truncated, "cut by mail.get, not by step 10");
            let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
            assert_eq!(v["truncated"], true);
            assert_eq!(v["uid"], 104);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn mail_get_cut_inside_the_password_leaks_no_prefix() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::SecretBody).await;
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    let secret = pass();
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let mut lengths = std::collections::BTreeSet::new();
    // Limits that cut the text before, inside and after the password.
    for max in (400..900).step_by(2) {
        let mut snap = snapshot((1, "implicit"), (ip, "implicit"));
        snap.config
            .services
            .get_mut("mail")
            .unwrap()
            .limits
            .max_response_bytes = Some(max);
        let (o, tr) = go(&c, &snap, &cat, &up).await;
        let Outcome::Done { finished, .. } = &o else {
            panic!("{o:?}")
        };
        let out = String::from_utf8_lossy(&finished.body).into_owned();
        for n in 4..=secret.len() {
            assert!(
                !out.contains(&secret[..n]),
                "max {max} leaks {:?}: {out}",
                &secret[..n]
            );
        }
        let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
        lengths.insert(v["text"].as_str().map_or(0, str::len));
        assert_no_secret(&c, &snap, &tr, &o);
    }
    // The cut moved across the whole password.
    assert!(lengths.len() > 100, "{}", lengths.len());
}

/// `mail.get` through the whole client on a 2 MiB thread, with an extra
/// BODYSTRUCTURE response `depth` parentheses deep.
fn get_with_nesting(depth: usize) -> Outcome {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(Box::pin(async move {
                let p = pki();
                let (ip, _log) = imap_server(&p, Imap::Nest(depth)).await;
                let snap = snapshot((1, "implicit"), (ip, "implicit"));
                let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
                Box::pin(go(
                    &c,
                    &snap,
                    &catalog_of(MANIFEST),
                    &upstream(&p, Duration::from_secs(5)),
                ))
                .await
                .0
            }))
        })
        .unwrap()
        .join()
        .expect("the call fits the stack")
}

#[test]
fn valid_bodystructure_32_deep_accepted_33_refused() {
    let o = get_with_nesting(32);
    assert_eq!(done(&o).0, 200);
    let o = get_with_nesting(33);
    assert!(failed(&o).contains("nested too deep"), "{o:?}");
}
