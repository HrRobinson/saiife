//! `saiife daemon --user`, the personal broker (plan 16, Task 5), end to
//! end: a real broker as the current user, every path in a temp dir, the
//! test keychain seam, a dead session bus, and a loopback HTTPS mock whose
//! CA is trusted through `<config dir>/ca/` (the user's own). Nothing
//! leaves loopback; no service manager runs; signals go to the test's own
//! child only.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{Opts, TestDaemon};
use common::personal::{mode, own_uid, wait_for, TestBroker};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use saiife_ipc::client::ClientError;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A fake secret value, built at run time (no token-shaped literal).
fn secret_value() -> String {
    concat!("personal", "-broker-", "value-", "4711").to_string()
}

fn refused(e: &ClientError) -> (String, String) {
    match e {
        ClientError::Refused { code, message, .. } => (code.clone(), message.clone()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn add_secret(b: &TestBroker, name: &str, services: &[&str]) {
    b.call(
        "secret.add",
        json!({"name": name, "kind": "header", "fields": {"value": secret_value()},
               "allowed_services": services}),
    )
    .unwrap_or_else(|e| panic!("secret.add: {e:?}; {}", b.stderr_text()));
}

fn all_bytes_under(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return out;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_bytes_under(&p));
        } else if let Ok(b) = fs::read(&p) {
            out.extend(b);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

// ---------------------------------------------------------------- mock

struct Mock {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
    ca_pem: String,
}

fn mock() -> Mock {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let h = hits.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (cfg, h) = (cfg.clone(), h.clone());
            std::thread::spawn(move || serve_one(cfg, tcp, h));
        }
    });
    Mock {
        port,
        hits,
        ca_pem: ca.pem(),
    }
}

fn serve_one(cfg: Arc<rustls::ServerConfig>, tcp: TcpStream, hits: Arc<Mutex<Vec<String>>>) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
    let conn = rustls::ServerConnection::new(cfg).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let len: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    hits.lock().unwrap().push(format!("{method} {path}"));
    let (status, body) = match method.as_str() {
        "POST" => (201, r#"{"created":true}"#),
        _ => (200, r#"{"ok":true}"#),
    };
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(resp.as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// A personal config with one `http` service on the mock: reads allowed,
/// writes asked, `reports:read` in no list. No `[[scope]]`: the implicit
/// `personal` scope lists it.
fn erp_config(port: u16) -> String {
    format!(
        r#"version = 2

[services.erp]
connector = "http"
base_url = "https://127.0.0.1:{port}/api"
secret = "erp-key"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = ["invoices:read"]
ask = ["invoices:write"]

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/invoices"

[[services.erp.operation]]
id = "invoices.create"
capability = "invoices:write"
kind = "write"
method = "POST"
path = "/invoices"
body = "json"

[[services.erp.operation]]
id = "reports.get"
capability = "reports:read"
kind = "read"
method = "GET"
path = "/reports"
"#
    )
}

/// A broker serving [`erp_config`] on a fresh mock, its CA in the user's
/// `<config dir>/ca/`, and the `erp-key` secret added.
fn erp_world() -> (TestBroker, Mock) {
    erp_world_with("")
}

/// [`erp_world`] with `extra` appended to the config.
fn erp_world_with(extra: &str) -> (TestBroker, Mock) {
    let m = mock();
    let mut b = TestBroker::prepare();
    b.write_config(&format!("{}{extra}", erp_config(m.port)));
    let ca = b.config_dir().join("ca");
    fs::create_dir(&ca).unwrap();
    fs::set_permissions(&ca, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(ca.join("test-ca.pem"), &m.ca_pem).unwrap();
    fs::set_permissions(ca.join("test-ca.pem"), fs::Permissions::from_mode(0o600)).unwrap();
    b.spawn_and_wait();
    add_secret(&b, "erp-key", &["erp"]);
    (b, m)
}

// ---------------------------------------------------------------- tests

#[test]
fn hello_mode_personal() {
    let b = TestBroker::start(None);
    let c = b.client();
    let h = c.hello_answer();
    assert_eq!(h["mode"], json!("personal"));
    assert_eq!(h["daemon"], json!(env!("CARGO_PKG_VERSION")));
    let s = b.call("status", json!({})).unwrap();
    assert_eq!(s["mode"], json!("personal"));
}

#[test]
fn socket_dir_0700_sockets_0600() {
    let b = TestBroker::start(None);
    assert_eq!(mode(&b.socket_dir()), 0o700);
    assert_eq!(mode(&b.socket()), 0o600);
    assert!(wait_for(Duration::from_secs(5), || b
        .gateway_socket()
        .exists()));
    assert_eq!(mode(&b.gateway_socket()), 0o600);
    assert_eq!(mode(&b.state_dir()), 0o700);
    assert_eq!(mode(&b.audit_dir()), 0o700);
}

#[test]
fn config_created_on_first_start() {
    let b = TestBroker::start(None);
    let text = fs::read_to_string(b.config()).unwrap();
    assert!(text.contains("version = 2"), "{text}");
    assert!(text.contains("not a security boundary"), "{text}");
    assert_eq!(mode(&b.config()), 0o600);
    assert_eq!(mode(&b.config_dir()), 0o700);
    // The minimal config is a valid policy.
    assert_eq!(b.call("status", json!({})).unwrap()["policy_ok"], true);
    let policy: Vec<Value> = b
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "policy")
        .collect();
    assert_eq!(policy[0]["result"], "loaded", "{policy:?}");
}

#[test]
fn config_dir_not_0700_refused_with_fix() {
    let b = TestBroker::prepare();
    fs::create_dir_all(b.config_dir()).unwrap();
    fs::set_permissions(b.config_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let o = b.run_to_exit();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(
        err.contains(&format!("chmod 700 {}", b.config_dir().display())),
        "{err}"
    );
    assert!(!b.config().exists());
    assert!(!b.socket().exists());
}

#[test]
fn secret_add_list_through_broker_as_own_user() {
    let b = TestBroker::start(None);
    add_secret(&b, "gh", &["github"]);
    let l = b.call("secret.list", json!({})).unwrap();
    let names: Vec<&str> = l["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["gh"]);
    assert_eq!(l["secrets"][0]["created_by"], json!(own_uid()));
    // The value is in neither the audit log nor the vault file.
    let audit = all_bytes_under(&b.audit_dir());
    assert!(!audit.is_empty());
    assert!(!contains(&audit, &secret_value()));
    let vault = fs::read(b.vault_file()).unwrap();
    assert!(!contains(&vault, &secret_value()));
    // The key is the keychain's only item, 32 bytes.
    let items: Vec<_> = fs::read_dir(b.keychain_dir()).unwrap().collect();
    assert_eq!(items.len(), 1);
    let add = b
        .records()
        .into_iter()
        .find(|r| r["kind"] == "secret" && r["event"] == "secret_add")
        .unwrap();
    assert_eq!(add["uid"], json!(own_uid()));
    assert_eq!(add["decision"], "allow");
}

#[test]
fn vault_survives_restart_same_key() {
    let mut b = TestBroker::start(None);
    add_secret(&b, "gh", &["github"]);
    let item = |b: &TestBroker| {
        let p = fs::read_dir(b.keychain_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::read(p).unwrap()
    };
    let key = item(&b);
    b.stop_clean();
    b.spawn_and_wait();
    assert_eq!(item(&b), key, "the vault key changed");
    let l = b.call("secret.list", json!({})).unwrap();
    assert_eq!(l["secrets"].as_array().unwrap().len(), 1, "{l:?}");
    assert!(b.events("vault_unavailable").is_empty());
}

#[test]
fn personal_without_keychain_serves_audit() {
    let mut b = TestBroker::prepare();
    // A file where the test keychain dir should be: the keychain errors.
    fs::write(b.keychain_dir(), b"not a dir").unwrap();
    b.spawn_and_wait();
    let r = b.wait_event("vault_unavailable");
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .contains("keychain unavailable"),
        "{r}"
    );
    let e = b
        .call(
            "secret.add",
            json!({"name": "gh", "kind": "header", "fields": {"value": secret_value()},
                   "allowed_services": ["github"]}),
        )
        .unwrap_err();
    let (code, _) = refused(&e);
    assert_ne!(code, "ok");
    // Audit still works.
    assert!(b.call("status", json!({})).unwrap()["head_seq"].is_u64());
    assert!(!b.vault_file().exists());
}

#[test]
fn harness_without_keychain_seam_never_reaches_desktop() {
    let mut b = TestBroker::prepare();
    b.env.push(("SAIIFE_TEST_KEYCHAIN".into(), None));
    b.spawn_and_wait();
    let mut reason = String::new();
    assert!(
        wait_for(Duration::from_secs(5), || {
            reason = b
                .events("vault_unavailable")
                .first()
                .and_then(|r| r["reason"].as_str().map(str::to_string))
                .unwrap_or_default();
            reason.contains("no session bus")
        }),
        "reason {reason:?}; stderr: {}",
        b.stderr_text()
    );
    assert!(!b.keychain_dir().exists());
}

#[test]
fn every_record_mode_personal() {
    let (b, m) = erp_world();
    let a = b
        .call(
            "api.call",
            json!({"service": "erp", "operation": "invoices.list"}),
        )
        .unwrap_or_else(|e| panic!("{e:?}; {}", b.stderr_text()));
    assert_eq!(a["status"], 200, "{a:?}");
    assert_eq!(m.hits.lock().unwrap().len(), 1);
    let recs = b.records();
    assert!(
        recs.iter().any(|r| r["kind"] == "connector"),
        "no connector record: {recs:?}"
    );
    for r in &recs {
        assert_eq!(r["mode"], "personal", "{r}");
    }
}

#[test]
fn implicit_scope_allows_configured_service() {
    let (b, m) = erp_world();
    let a = b
        .call(
            "api.call",
            json!({"service": "erp", "operation": "invoices.list"}),
        )
        .unwrap_or_else(|e| panic!("{e:?}; {}", b.stderr_text()));
    assert_eq!(a["status"], 200, "{a:?}");
    assert_eq!(m.hits.lock().unwrap().as_slice(), ["GET /api/invoices"]);
    let conn: Vec<Value> = b
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(conn[0]["decision"], "allow", "{}", conn[0]);
    assert_eq!(conn[0]["uid"], json!(own_uid()), "{}", conn[0]);
    // A service the config does not name is outside the implicit scope.
    let e = b
        .call(
            "api.call",
            json!({"service": "nope", "operation": "invoices.list"}),
        )
        .unwrap_err();
    assert_ne!(refused(&e).0, "ok");
}

#[test]
fn project_allow_overlay_honoured() {
    let (b, m) = erp_world();
    // `reports:read` is in no system list: denied by default.
    let e = b
        .call(
            "api.call",
            json!({"service": "erp", "operation": "reports.get"}),
        )
        .unwrap_err();
    assert_eq!(refused(&e).0, "denied", "{e:?}");
    // A project overlay may allow it here, as in developer mode.
    let a = b
        .call(
            "api.call",
            json!({"service": "erp", "operation": "reports.get",
                   "overlay": {"allow": ["reports:read"]}}),
        )
        .unwrap_or_else(|e| panic!("{e:?}; {}", b.stderr_text()));
    assert_eq!(a["status"], 200, "{a:?}");
    assert_eq!(m.hits.lock().unwrap().as_slice(), ["GET /api/reports"]);
}

#[test]
fn same_user_approval_allowed() {
    let (b, m) = erp_world();
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(br#"{"amount":5}"#);
    let a = b
        .call(
            "api.call",
            json!({"service": "erp", "operation": "invoices.create", "body_b64": body}),
        )
        .unwrap_or_else(|e| panic!("{e:?}; {}", b.stderr_text()));
    let id = a["pending"].as_u64().unwrap_or_else(|| panic!("{a:?}"));
    assert!(m.hits.lock().unwrap().is_empty());
    let d = b
        .call(
            "approval.decide",
            json!({"request": id, "action": "approve"}),
        )
        .unwrap_or_else(|e| panic!("{e:?}; {}", b.stderr_text()));
    assert_eq!(d["state"], "approved", "{d:?}");
    let mut state = Value::Null;
    assert!(
        wait_for(Duration::from_secs(10), || {
            state = b
                .call("api.result", json!({"request": id}))
                .map(|r| r["state"].clone())
                .unwrap_or(Value::Null);
            state == "sent"
        }),
        "state {state}; {}",
        b.stderr_text()
    );
    assert_eq!(m.hits.lock().unwrap().as_slice(), ["POST /api/invoices"]);
}

#[test]
fn audit_chain_has_no_key_and_verifies() {
    let mut b = TestBroker::start(None);
    add_secret(&b, "gh", &["github"]);
    b.stop_clean();
    let recs = b.records();
    let genesis = &recs[0];
    assert_eq!(genesis["kind"], "genesis", "{genesis}");
    assert!(genesis["key"].is_null(), "{genesis}");
    assert!(!recs.iter().any(|r| r["kind"] == "checkpoint"), "{recs:?}");
    assert!(!b.state_dir().join("keys").exists());
    assert!(!b.events("stop").is_empty(), "{recs:?}");
    let o = b.verify();
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{out}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // The label is the chain's own mode, not "developer mode".
    assert!(
        out.contains("personal broker: no signing key, so this catches accidental edits"),
        "{out}"
    );
    assert!(!out.contains("developer mode"), "{out}");
}

#[test]
fn personal_reload_with_locked_rejected() {
    let b = TestBroker::start(None);
    let before = b.call("status", json!({})).unwrap();
    assert_eq!(before["policy_ok"], true);
    b.write_config("version = 2\nlocked = true\n");
    let a = b.call("policy.reload", json!({})).unwrap();
    assert_eq!(a["result"], "rejected", "{a:?}");
    assert!(
        a["reason"].as_str().unwrap().contains("locked = true"),
        "{a:?}"
    );
    // The old policy stays in force, and the record says `rejected`.
    let after = b.call("status", json!({})).unwrap();
    assert_eq!(after["policy_ok"], true);
    assert_eq!(after["policy"], before["policy"]);
    let policy: Vec<Value> = b
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "policy")
        .collect();
    let last = policy.last().unwrap();
    assert_eq!(last["result"], "rejected", "{policy:?}");
    assert!(
        last["reason"].as_str().unwrap().contains("locked = true"),
        "{last}"
    );
    assert!(b.events("reload_warning").is_empty());
}

#[test]
fn gateway_tcp_ignored_in_personal() {
    let b = TestBroker::prepare();
    b.write_config("version = 2\n\n[gateway]\ntcp = \"127.0.0.1:0\"\n");
    let mut b = b;
    b.spawn_and_wait();
    let s = b.call("status", json!({})).unwrap();
    assert_eq!(s["policy_ok"], true, "{s:?}");
    assert_eq!(s["gateway_tcp"], Value::Null, "{s:?}");
    assert!(b.events("gateway_tcp").is_empty());
    assert!(b.events("gateway_tcp_failed").is_empty());
    assert!(
        b.stderr_text().contains("[gateway] tcp is ignored"),
        "{}",
        b.stderr_text()
    );
}

#[test]
fn user_refuses_path_flags() {
    let b = TestBroker::prepare();
    for flag in ["--config", "--state-dir", "--credentials-dir"] {
        let o = b
            .command()
            .arg(flag)
            .arg(b.path().join("elsewhere"))
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{flag}: {err}");
        assert!(err.contains(flag), "{flag}: {err}");
        assert!(!b.socket_dir().exists());
        assert!(!b.keychain_dir().exists());
        assert!(!b.path().join("elsewhere").exists());
    }
}

#[test]
fn rotate_key_refused_without_record() {
    let b = TestBroker::start(None);
    let before = b.records().len();
    let e = b.call("audit.rotate_key", json!({})).unwrap_err();
    let (_, msg) = refused(&e);
    assert!(msg.contains("no signing key"), "{msg}");
    std::thread::sleep(Duration::from_millis(200));
    let recs = b.records();
    assert_eq!(recs.len(), before, "{:?}", &recs[before..]);
    assert!(!recs.iter().any(|r| r["kind"] == "key_rotate"));
    assert!(!b.state_dir().join("keys").exists());
}

#[test]
fn personal_refused_as_locked_config() {
    let b = TestBroker::prepare();
    b.write_config("version = 2\nlocked = true\n");
    let o = b.run_to_exit();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("locked = true"), "{err}");
    assert!(!b.socket_dir().exists());
    assert!(!b.keychain_dir().exists());
}

#[test]
fn personal_refused_on_locked_host() {
    let b = TestBroker::prepare();
    fs::write(b.locked_marker(), "installed = true\n").unwrap();
    let o = b.run_to_exit();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("locked mode"), "{err}");
    assert!(
        err.contains(&b.locked_marker().display().to_string()),
        "{err}"
    );
    // Refused before the keychain was opened (the test keychain would have
    // made its dir) and before anything else was created.
    assert!(!b.keychain_dir().exists());
    assert!(!b.socket_dir().exists());
    assert!(!b.config().exists());
    assert!(!b.state_dir().exists());
}

#[test]
fn personal_refuses_bad_runtime_dir() {
    let b = TestBroker::prepare();
    fs::set_permissions(b.runtime_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let o = b.run_to_exit();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(
        err.contains(&b.runtime_dir().display().to_string()),
        "{err}"
    );
    assert!(!b.socket_dir().exists());
    assert!(!b.keychain_dir().exists());
    // Unset: refused too, never a fallback to /tmp.
    let mut b = TestBroker::prepare();
    b.env.push(("XDG_RUNTIME_DIR".into(), None));
    let o = b.run_to_exit();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
    assert!(!b.keychain_dir().exists());
}

#[test]
fn second_broker_refused_before_keychain() {
    let b = TestBroker::start(None);
    // A second broker of the same user, with a fresh keychain: refused by
    // the state lock before it reads or stores any key.
    let other_kc = b.path().join("k2");
    let mut cmd = b.command();
    cmd.env("SAIIFE_TEST_KEYCHAIN", &other_kc);
    let o = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("another personal broker"), "{err}");
    // Its keychain may exist (opened by the CLI) but holds no key.
    let items = fs::read_dir(&other_kc).map(|r| r.count()).unwrap_or(0);
    assert_eq!(items, 0);
    // The first broker still answers.
    assert!(b.call("status", json!({})).is_ok());
}

#[test]
fn local_connector_owned_by_user_loads() {
    let mut b = TestBroker::prepare();
    let dir = b.config_dir().join("connectors");
    fs::create_dir_all(&dir).unwrap();
    for d in [b.path().join("c/saiife"), b.config_dir(), dir.clone()] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let manifest = include_str!("../../broker/connectors/test-echo.toml").replacen(
        "id = \"test-echo\"",
        "id = \"my-echo\"",
        1,
    );
    fs::write(dir.join("my-echo.toml"), manifest).unwrap();
    fs::set_permissions(dir.join("my-echo.toml"), fs::Permissions::from_mode(0o600)).unwrap();
    b.write_config(
        "version = 2\n\n[services.mine]\nconnector = \"my-echo\"\nsecret = \"echo\"\nparams = { shop = \"acme\" }\nallow = [\"orders:read\"]\n",
    );
    b.spawn_and_wait();
    let s = b.call("status", json!({})).unwrap();
    assert_eq!(s["policy_ok"], true, "{s:?}; {}", b.stderr_text());
    let l = b.call("api.list", json!({})).unwrap();
    assert!(l.to_string_lossy_contains("mine"), "{l:?}");
}

trait LossyContains {
    fn to_string_lossy_contains(&self, s: &str) -> bool;
}
impl LossyContains for serde_json::Map<String, Value> {
    fn to_string_lossy_contains(&self, s: &str) -> bool {
        Value::Object(self.clone()).to_string().contains(s)
    }
}

#[test]
fn secret_import_refused_personal() {
    let b = TestBroker::start(None);
    let e = b
        .call(
            "secret.add",
            json!({"name": "gh", "kind": "header", "fields": {"value": secret_value()},
                   "allowed_services": ["github"],
                   "backup": {"path": "/h/.env", "bytes_b64": "QT0xCg=="}}),
        )
        .unwrap_err();
    let (_, msg) = refused(&e);
    assert_eq!(msg, "personal broker: use secret add");
    assert!(!b.state_dir().join("state/import-backup").exists());
    let l = b.call("secret.list", json!({})).unwrap();
    assert_eq!(l["secrets"], json!([]));
}

#[test]
fn print_unit_systemd_and_launchd() {
    let exe = fs::canonicalize(env!("CARGO_BIN_EXE_saiife")).unwrap();
    let b = TestBroker::prepare();
    for (kind, want) in [
        (
            "systemd",
            saiife_system::user_unit::user_unit_text(&exe).unwrap(),
        ),
        (
            "launchd",
            saiife_system::user_unit::launchd_plist_text(&exe).unwrap(),
        ),
    ] {
        let o = b.command().args(["--print-unit", kind]).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{kind}");
        assert_eq!(String::from_utf8_lossy(&o.stdout), want, "{kind}");
        // Nothing written, no broker started.
        assert!(!b.socket_dir().exists());
        assert!(!b.config().exists());
        assert!(!b.keychain_dir().exists());
    }
    // --print-unit needs --user.
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["daemon", "--system", "--print-unit", "systemd"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn locked_records_still_locked() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    common::daemon::append(&mut c, common::daemon::guard_rec("echo hi")).unwrap();
    assert_eq!(c.hello_answer()["mode"], json!("locked"));
    let recs = d.records();
    assert!(recs.len() > 2);
    for r in recs {
        assert_eq!(r["mode"], "locked", "{r}");
    }
}

// ------------------------------------------------- the CLI (Task 6)

fn out(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The secret value in a 0600 file under the test dir.
fn value_file(b: &TestBroker, name: &str, value: &str) -> std::path::PathBuf {
    let p = b.path().join(name);
    fs::write(&p, value).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn assert_no_value(b: &TestBroker, outs: &[&std::process::Output], value: &str) {
    for o in outs {
        assert!(!out(o).contains(value), "stdout leaked the value");
        assert!(!err(o).contains(value), "stderr leaked the value");
    }
    assert!(!contains(&all_bytes_under(&b.audit_dir()), value));
}

fn names(b: &TestBroker) -> Vec<String> {
    let l = b.call("secret.list", json!({})).unwrap();
    l["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn secret_add_list_rotate_remove_personal() {
    let b = TestBroker::start(None);
    let v1 = secret_value();
    let v2 = concat!("personal", "-rotated-", "value-", "0815").to_string();
    let f1 = value_file(&b, "v1", &v1);
    let f2 = value_file(&b, "v2", &v2);
    let add = b.run_cli(&[
        "secret",
        "add",
        "gh",
        "--kind",
        "token",
        "--service",
        "github",
        "--from-file",
        f1.to_str().unwrap(),
    ]);
    assert_eq!(add.status.code(), Some(0), "{}", err(&add));
    assert_eq!(out(&add), "added gh\n");
    let list = b.run_cli(&["secret", "list", "--json"]);
    assert_eq!(list.status.code(), Some(0), "{}", err(&list));
    let v: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["secrets"][0]["name"], "gh");
    assert_eq!(v["secrets"][0]["allowed_services"], json!(["github"]));
    let rot = b.run_cli(&[
        "secret",
        "rotate",
        "gh",
        "--from-file",
        f2.to_str().unwrap(),
    ]);
    assert_eq!(rot.status.code(), Some(0), "{}", err(&rot));
    assert_eq!(out(&rot), "rotated gh\n");
    let rm = b.run_cli(&["secret", "remove", "gh"]);
    assert_eq!(rm.status.code(), Some(0), "{}", err(&rm));
    assert_eq!(out(&rm), "removed gh\n");
    let empty = b.run_cli(&["secret", "list"]);
    assert_eq!(out(&empty), "no secrets\n");
    assert_no_value(&b, &[&add, &list, &rot, &rm, &empty], &v1);
    assert_no_value(&b, &[&add, &list, &rot, &rm, &empty], &v2);
    // The records are the broker's, as the own uid.
    let adds: Vec<Value> = b
        .records()
        .into_iter()
        .filter(|r| r["event"] == "secret_add")
        .collect();
    assert_eq!(adds.len(), 1, "{adds:?}");
    assert_eq!(adds[0]["uid"], json!(own_uid()));
    assert_eq!(adds[0]["mode"], "personal");
}

#[test]
fn connect_personal_writes_policy_0600_and_secret() {
    let b = TestBroker::start(None);
    let o = b
        .cli(&[
            "connect",
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "PB_TOKEN",
        ])
        .env("PB_TOKEN", secret_value())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let file = b.config_dir().join("policy.d/shopify.toml");
    assert!(out(&o).contains("added shopify"), "{}", out(&o));
    assert!(out(&o).contains(&file.display().to_string()), "{}", out(&o));
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(&b.config_dir().join("policy.d")), 0o700);
    let text = fs::read_to_string(&file).unwrap();
    assert!(text.contains("[services.shopify]"), "{text}");
    assert_eq!(names(&b), ["shopify"]);
    assert_no_value(&b, &[&o], &secret_value());
    // The broker loads it.
    let r = b.run_cli(&["policy", "reload"]);
    assert_eq!(r.status.code(), Some(0), "{}{}", out(&r), err(&r));
}

/// The CLI's XDG_CONFIG_HOME differs from the broker's (a systemd user unit
/// started with another environment): connect warns and writes where the
/// broker reads, which its `status` names.
#[test]
fn connect_personal_uses_the_brokers_config_and_warns() {
    let b = TestBroker::start(None);
    let st = b.call("status", json!({})).unwrap();
    assert_eq!(st["config"], json!(b.config().display().to_string()));
    let other = b.path().join("other-config");
    let o = b
        .cli(&[
            "connect",
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "PB_TOKEN",
        ])
        .env("XDG_CONFIG_HOME", &other)
        .env("PB_TOKEN", secret_value())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(
        err(&o).contains(&format!(
            "the personal broker reads {}",
            b.config().display()
        )),
        "{}",
        err(&o)
    );
    assert!(b.config_dir().join("policy.d/shopify.toml").exists());
    assert!(!other.exists());
    let r = b.run_cli(&["policy", "reload"]);
    assert_eq!(r.status.code(), Some(0), "{}{}", out(&r), err(&r));
}

#[test]
fn connect_personal_without_config_says_start_broker() {
    let b = TestBroker::prepare();
    let o = b
        .cli(&[
            "connect",
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "PB_TOKEN",
        ])
        .env("PB_TOKEN", secret_value())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(
        err(&o).contains("start the broker first: saiife daemon --user"),
        "{}",
        err(&o)
    );
    assert!(!b.config_dir().exists());
}

#[test]
fn api_call_through_broker_loopback_mock() {
    let (b, m) = erp_world();
    let o = b.run_cli(&["api", "erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).contains(r#"{"ok":true}"#), "{}", out(&o));
    assert_eq!(m.hits.lock().unwrap().as_slice(), ["GET /api/invoices"]);
    // Developer-mode overlays: the project may allow (spec §6.9.1).
    let project = b.path().join("p");
    fs::create_dir_all(project.join(".saiife")).unwrap();
    fs::write(
        project.join(".saiife/config.toml"),
        "version = 2\n[services.erp]\nallow = [\"reports:read\"]\n",
    )
    .unwrap();
    let o = b.run_cli(&["api", "erp", "reports.get"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        m.hits.lock().unwrap().as_slice(),
        ["GET /api/invoices", "GET /api/reports"]
    );
    assert_no_value(&b, &[&o], &secret_value());
}

#[test]
fn run_secret_through_broker() {
    let Ok(bin) = fs::canonicalize("/usr/bin/printenv") else {
        eprintln!("skipped: no printenv");
        return;
    };
    if bin.file_name().unwrap() != "printenv"
        || saiife_system::fsops::root_owned_chain(&bin).is_err()
    {
        eprintln!("skipped: printenv is not a root-owned file of its own here");
        return;
    }
    let m = mock();
    let mut b = TestBroker::prepare();
    b.write_config(&format!(
        "{}\n[secrets.erp-key]\nrun_allow = [{:?}]\n",
        erp_config(m.port),
        bin.display().to_string()
    ));
    b.spawn_and_wait();
    add_secret(&b, "erp-key", &["erp"]);
    let o = b
        .cli(&[
            "run",
            "--secret",
            "erp-key:TOKEN",
            "--",
            "printenv",
            "TOKEN",
        ])
        .env("PATH", bin.parent().unwrap())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), "[MASKED]\n");
    assert_no_value(&b, &[&o], &secret_value());
}

#[test]
fn policy_reload_personal() {
    let b = TestBroker::start(None);
    let o = b.run_cli(&["policy", "reload"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), "loaded\n");
    // A locked-mode config is rejected; the old policy stays.
    b.write_config("version = 2\nlocked = true\n");
    let o = b.run_cli(&["policy", "reload"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(out(&o).starts_with("rejected: "), "{}", out(&o));
}

#[test]
fn audit_broker_lists_and_verifies() {
    let b = TestBroker::start(None);
    add_secret(&b, "gh", &["github"]);
    let label = "personal broker, not a security boundary";
    let o = b.run_cli(&["audit", "--broker"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let text = out(&o);
    assert!(text.lines().next().unwrap().contains(label), "{text}");
    assert!(
        text.contains(&b.audit_dir().display().to_string()),
        "{text}"
    );
    let v = b.run_cli(&["audit", "verify", "--broker"]);
    assert_eq!(v.status.code(), Some(0), "{}{}", out(&v), err(&v));
    let vt = out(&v);
    assert!(vt.starts_with("audit chain: intact"), "{vt}");
    for line in vt
        .lines()
        .filter(|l| l.starts_with("audit chain") || l.contains("log:"))
    {
        assert!(line.contains(label), "{line}");
    }
    assert!(vt.contains(&b.audit_dir().display().to_string()), "{vt}");
    // Without --broker the developer log is read, not the broker's.
    let absent = common::absent_system_config(b.path());
    let dev = b.run_cli(&[
        "audit",
        "verify",
        "--system-config",
        absent.to_str().unwrap(),
    ]);
    assert!(!out(&dev).contains(&b.audit_dir().display().to_string()));
}

#[test]
fn status_shows_personal_broker() {
    let mut b = TestBroker::start(None);
    let sysroot = b.path().join("sysroot");
    fs::create_dir_all(&sysroot).unwrap();
    let line = "  personal broker: running (not a security boundary)";
    let o = b.run_cli(&["status", "--root", sysroot.to_str().unwrap()]);
    assert!(out(&o).lines().any(|l| l == line), "{}", out(&o));
    b.stop();
    let o = b.run_cli(&["status", "--root", sysroot.to_str().unwrap()]);
    assert!(!out(&o).contains("personal broker"), "{}", out(&o));
}

#[test]
fn secret_import_refused_personal_cli() {
    let b = TestBroker::start(None);
    let env = b.home().join(".env");
    let text = format!("GITHUB_TOKEN={}\n", secret_value());
    fs::write(&env, &text).unwrap();
    let me = common::daemon::own_user();
    let o = b.run_cli(&[
        "secret",
        "import",
        "--user",
        &me,
        "--home",
        b.home().to_str().unwrap(),
        "--yes-to",
        env.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(err(&o), "saiife: personal broker: use secret add\n");
    assert_eq!(fs::read_to_string(&env).unwrap(), text);
    assert_eq!(names(&b), Vec::<String>::new());
}

#[test]
fn broker_down_message() {
    let b = TestBroker::prepare();
    b.write_config("version = 2\n");
    let o = b.run_cli(&["secret", "list"]);
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert_eq!(
        err(&o),
        format!(
            "saiife: cannot reach the personal broker at {}: start it with saiife daemon --user (docs/personal-broker.md)\n",
            b.socket_dir().display()
        )
    );
    let o = b.run_cli(&["api", "erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(
        err(&o).contains("start it with saiife daemon --user"),
        "{}",
        err(&o)
    );
}

/// A locked daemon (own uid, an admin) for the resolver tests.
fn locked_admin() -> TestDaemon {
    TestDaemon::start(Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", common::daemon::own_group()),
        ..Opts::default()
    })
}

#[test]
fn locked_system_config_wins_over_running_broker() {
    let d = locked_admin();
    let b = TestBroker::start(None);
    add_secret(&b, "gh", &["github"]);
    // The host's system config says locked: the CLI goes to the locked
    // daemon, never to the broker that is up on $XDG_RUNTIME_DIR.
    let list = b
        .cli(&["secret", "list", "--json"])
        .env("SAIIFE_TEST_SYSTEM_CONFIG", d.config())
        .output()
        .unwrap();
    assert_eq!(list.status.code(), Some(0), "{}", err(&list));
    let v: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["secrets"], json!([]), "the broker answered: {v}");
    let f = value_file(&b, "v", &secret_value());
    let add = b
        .cli(&[
            "secret",
            "add",
            "locked-one",
            "--kind",
            "token",
            "--service",
            "github",
            "--from-file",
            f.to_str().unwrap(),
        ])
        .env("SAIIFE_TEST_SYSTEM_CONFIG", d.config())
        .output()
        .unwrap();
    assert_eq!(add.status.code(), Some(0), "{}", err(&add));
    assert_eq!(names(&b), ["gh"]);
    let locked_adds = d
        .records()
        .into_iter()
        .filter(|r| r["event"] == "secret_add")
        .count();
    assert_eq!(locked_adds, 1, "{:?}", d.records());
    // The broker saw one add only: the test's own `gh`.
    let broker_adds = b
        .records()
        .into_iter()
        .filter(|r| r["event"] == "secret_add")
        .count();
    assert_eq!(broker_adds, 1);
}

#[test]
fn locked_daemon_at_personal_socket_is_not_a_broker() {
    let d = locked_admin();
    let b = TestBroker::prepare();
    b.write_config("version = 2\n");
    // The locked daemon's bound socket dir, moved to where the broker's
    // would be and made 0700: every dir and uid check passes, only the
    // hello (`mode = "locked"`) tells it apart.
    fs::rename(d.socket_dir(), b.socket_dir()).unwrap();
    fs::set_permissions(b.socket_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    let f = value_file(&b, "v", &secret_value());
    let o = b.run_cli(&[
        "secret",
        "add",
        "gh",
        "--kind",
        "token",
        "--service",
        "github",
        "--from-file",
        f.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(err(&o).contains("not a personal broker"), "{}", err(&o));
    let adds: Vec<Value> = d
        .records()
        .into_iter()
        .filter(|r| r["event"] == "secret_add")
        .collect();
    assert!(adds.is_empty(), "{adds:?}");
}

/// Plan 14 environments through the personal broker: `saiife api` sends the
/// project's `env`, and the broker (developer-mode decisions) runs the call
/// under that environment's snapshot. An undefined `env` is the base config
/// with a warning.
#[test]
fn project_env_picks_snapshot_via_cli() {
    let (b, m) = erp_world_with(
        "\n[environments.staging]\nservices.erp.allow = [\"invoices:read\", \"reports:read\"]\n",
    );
    let project = b.path().join("p");
    fs::create_dir_all(project.join(".saiife")).unwrap();
    // No project env: the base config, where `reports:read` is in no list.
    let o = b.run_cli(&["api", "erp", "reports.get"]);
    assert_eq!(o.status.code(), Some(2), "{} / {}", out(&o), err(&o));
    fs::write(
        project.join(".saiife/config.toml"),
        "version = 2\nenv = \"staging\"\n",
    )
    .unwrap();
    let o = b.run_cli(&["api", "erp", "reports.get"]);
    assert_eq!(o.status.code(), Some(0), "{} / {}", out(&o), err(&o));
    assert_eq!(m.hits.lock().unwrap().as_slice(), ["GET /api/reports"]);
    let conn: Vec<Value> = b
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    let last = conn.last().unwrap();
    assert_eq!(last["env"], "staging", "{last}");
    assert_eq!(last["decision"], "allow", "{last}");
    // `api --list` takes the same snapshot.
    let o = b.run_cli(&["api", "--list", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let action = v["services"][0]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["id"] == "reports.get")
        .map(|op| op["action"].clone());
    assert_eq!(action, Some(json!("allow")), "{v}");
    // An env the broker config does not define: the base, with a warning.
    fs::write(
        project.join(".saiife/config.toml"),
        "version = 2\nenv = \"qa\"\n",
    )
    .unwrap();
    let o = b.run_cli(&["api", "erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(err(&o).contains("\"qa\" is not defined"), "{}", err(&o));
    let o = b.run_cli(&["api", "erp", "reports.get"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
}
