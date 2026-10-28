//! `saiife secret add|list|rotate|remove` against a real daemon on temp
//! dirs (plan 10, Task 5). The daemon runs as the test user; admin ops
//! authorize through `[admin] groups = [<primary group>]`.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, Opts, TestDaemon};
use serde_json::{json, Value};
use std::fs;
use std::process::{Command, Output, Stdio};

fn admin() -> TestDaemon {
    TestDaemon::start(Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    })
}

fn saiife(d: &TestDaemon, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null());
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn list_json(d: &TestDaemon) -> Value {
    let o = saiife(d, &["list", "--json"], &[]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    serde_json::from_slice(&o.stdout).unwrap()
}

fn secret_records(d: &TestDaemon) -> Vec<Value> {
    d.of_kind("secret")
}

#[test]
fn add_list_remove_round_trip() {
    let d = admin();
    let o = saiife(
        &d,
        &[
            "add",
            "github-main",
            "--kind",
            "token",
            "--service",
            "github",
            "--service",
            "gh2",
            "--from-env",
            "SV",
        ],
        &[("SV", "ghp_value_0001")],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));

    let l = list_json(&d);
    let s = &l["secrets"][0];
    assert_eq!(s["name"], "github-main");
    assert_eq!(s["kind"], "token");
    assert_eq!(s["allowed_services"], json!(["github", "gh2"]));
    assert!(s["created"].is_string());
    assert!(s["last_used"].is_null());
    assert_eq!(
        s["created_by"].as_u64(),
        Some(common::daemon::own_uid() as u64)
    );
    assert!(s.get("fields").is_none());

    // The text list shows the name and kind.
    let t = saiife(&d, &["list"], &[]);
    assert_eq!(t.status.code(), Some(0));
    let t = String::from_utf8_lossy(&t.stdout).into_owned();
    assert!(t.contains("github-main") && t.contains("token"), "{t}");

    // A second add of the same name is refused; rotate replaces.
    let o = saiife(
        &d,
        &[
            "add",
            "github-main",
            "--kind",
            "token",
            "--service",
            "github",
            "--from-env",
            "SV",
        ],
        &[("SV", "ghp_value_0002")],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("exists"), "{}", err(&o));
    let o = saiife(
        &d,
        &["rotate", "github-main", "--from-env", "SV"],
        &[("SV", "ghp_value_0003")],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let l = list_json(&d);
    assert_eq!(
        l["secrets"][0]["allowed_services"],
        json!(["github", "gh2"])
    );

    let o = saiife(&d, &["remove", "github-main"], &[]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(list_json(&d)["secrets"], json!([]));
    let o = saiife(&d, &["remove", "github-main"], &[]);
    assert_eq!(o.status.code(), Some(2));
    let o = saiife(
        &d,
        &["rotate", "github-main", "--from-env", "SV"],
        &[("SV", "ghp_value_0004")],
    );
    assert_eq!(o.status.code(), Some(2));

    let ev: Vec<(String, String)> = secret_records(&d)
        .iter()
        .map(|r| {
            assert_eq!(r["tool"], "secret");
            assert_eq!(r["decision"], "allow");
            assert_eq!(r["name"], "github-main");
            (
                r["event"].as_str().unwrap().into(),
                r["input"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        ev,
        vec![
            (
                "secret_add".to_string(),
                "secret_add github-main".to_string()
            ),
            (
                "secret_rotate".to_string(),
                "secret_rotate github-main".to_string()
            ),
            (
                "secret_remove".to_string(),
                "secret_remove github-main".to_string()
            ),
        ]
    );
    let v = d.verify();
    assert_eq!(v.status.code(), Some(0));
}

#[test]
fn non_admin_add_is_forbidden_and_recorded() {
    let d = TestDaemon::start(Opts {
        extra: "[admin]\ngroups = []\n".into(),
        ..Opts::default()
    });
    for args in [
        &[
            "add",
            "k1",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-env",
            "SV",
        ][..],
        &["list"][..],
        &["remove", "k1"][..],
        &["rotate", "k1", "--from-env", "SV"][..],
    ] {
        let o = saiife(&d, args, &[("SV", "valuevalue")]);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", err(&o));
        assert!(!err(&o).contains("valuevalue"));
    }
    let recs = secret_records(&d);
    assert!(!recs.is_empty());
    let add = recs.iter().find(|r| r["event"] == "secret_add").unwrap();
    assert_eq!(add["decision"], "deny");
    assert_eq!(add["tool"], "secret");
    assert_eq!(add["input"], "secret_add k1");
    assert_eq!(add["uid"].as_u64(), Some(common::daemon::own_uid() as u64));
    let rot = recs.iter().find(|r| r["event"] == "secret_rotate").unwrap();
    assert_eq!(rot["decision"], "deny");
    assert_eq!(rot["input"], "secret_rotate k1");
    assert_eq!(rot["name"], "k1");
    let rem = recs.iter().find(|r| r["event"] == "secret_remove").unwrap();
    assert_eq!(rem["input"], "secret_remove k1");
    let all = serde_json::to_string(&recs).unwrap();
    assert!(!all.contains("valuevalue"));
}

#[test]
fn value_never_in_audit_or_stderr() {
    let d = admin();
    let v1 = "Zq9-never-leak-VALUE-1";
    let v2 = "Zq9-never-leak-VALUE-2";
    let outs = vec![
        saiife(
            &d,
            &[
                "add",
                "leak",
                "--kind",
                "token",
                "--service",
                "s",
                "--from-env",
                "SV",
            ],
            &[("SV", v1)],
        ),
        saiife(&d, &["list", "--json"], &[]),
        saiife(&d, &["rotate", "leak", "--from-env", "SV"], &[("SV", v2)]),
        // Refusals must not echo the value either.
        saiife(
            &d,
            &[
                "add",
                "leak",
                "--kind",
                "token",
                "--service",
                "s",
                "--from-env",
                "SV",
            ],
            &[("SV", v1)],
        ),
        saiife(
            &d,
            &[
                "add",
                "bad name",
                "--kind",
                "token",
                "--service",
                "s",
                "--from-env",
                "SV",
            ],
            &[("SV", v2)],
        ),
        saiife(
            &d,
            &[
                "add",
                "oauth",
                "--kind",
                "oauth2",
                "--service",
                "s",
                "--from-env",
                "SV",
            ],
            &[("SV", v2)],
        ),
        saiife(&d, &["list"], &[]),
        saiife(&d, &["remove", "leak"], &[]),
        saiife(&d, &["remove", "leak"], &[]),
    ];
    let mut hay: Vec<u8> = Vec::new();
    for o in &outs {
        hay.extend(&o.stdout);
        hay.extend(&o.stderr);
    }
    for e in fs::read_dir(d.audit_dir()).unwrap() {
        hay.extend(fs::read(e.unwrap().path()).unwrap());
    }
    hay.extend(d.stderr_text().as_bytes());
    let text = String::from_utf8_lossy(&hay).into_owned();
    for v in [v1, v2] {
        for needle in [v.to_string(), b64(v.as_bytes())] {
            assert!(!text.contains(&needle), "{needle} found");
        }
    }
    let vault = fs::read(d.state_dir().join("vault/vault.bin")).unwrap();
    assert!(!String::from_utf8_lossy(&vault).contains(v2));
}

#[test]
fn add_refuses_when_vault_undecryptable() {
    let mut d = TestDaemon::prepare(&Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    });
    let vdir = d.state_dir().join("vault");
    fs::create_dir_all(&vdir).unwrap();
    let vfile = vdir.join("vault.bin");
    fs::write(
        &vfile,
        b"this is not a vault at all, not even close........",
    )
    .unwrap();
    let before = fs::read(&vfile).unwrap();
    d.spawn_and_wait();
    let o = saiife(
        &d,
        &[
            "add",
            "k1",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-env",
            "SV",
        ],
        &[("SV", "valuevalue")],
    );
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    let want = format!(
        "vault cannot be read; restore it or remove {} by hand",
        vfile.display()
    );
    assert!(err(&o).contains(&want), "{}", err(&o));
    for args in [&["list"][..], &["remove", "k1"][..]] {
        let o = saiife(&d, args, &[]);
        assert_eq!(o.status.code(), Some(2));
        assert!(err(&o).contains(&want));
    }
    assert_eq!(fs::read(&vfile).unwrap(), before);
}

#[test]
fn from_env_refused_for_multi_field() {
    let d = admin();
    for kind in ["aws", "gcp_sa", "azure_sp"] {
        let o = saiife(
            &d,
            &[
                "add",
                "k1",
                "--kind",
                kind,
                "--service",
                "s",
                "--from-env",
                "SV",
            ],
            &[("SV", "valuevalue-leaky")],
        );
        assert_eq!(o.status.code(), Some(2), "{kind}");
        let e = err(&o);
        assert!(
            e.contains("several fields") && e.contains("--from-file"),
            "{e}"
        );
        assert!(!e.contains("valuevalue-leaky"));
    }
    assert_eq!(list_json(&d)["secrets"], json!([]));
    // The daemon refuses a bad aws secret too, without quoting it.
    let mut c = d.client();
    let e = c
        .call(
            "secret.add",
            serde_json::from_value(json!({
                "name": "k1", "kind": "aws",
                "fields": {"token": "valuevalue-leaky"}, "allowed_services": ["s"]
            }))
            .unwrap(),
            common::daemon::dl(),
        )
        .unwrap_err();
    assert!(e.to_string().contains("this kind takes the fields"), "{e}");
    assert!(!e.to_string().contains("valuevalue-leaky"));
}

#[test]
fn cloud_kinds_added_from_files_never_leak() {
    let d = admin();
    let akid = concat!("AKI", "A", "TESTTESTTEST0001");
    let sk = concat!("test-secret-", "access-key-0001");
    let pem = concat!(
        "-----BEGIN ",
        "PRIVATE KEY-----\nTESTBODYTESTBODY0001\n-----END ",
        "PRIVATE KEY-----\n"
    );
    let cs = concat!("client-", "secret-0001");
    let g = "0123abcd-4567-89ab-cdef-0123456789ab";
    let files = [
        (
            "aws",
            "ak",
            json!({"access_key_id": akid, "secret_access_key": sk}),
        ),
        (
            "gcp_sa",
            "gk",
            json!({"type": "service_account", "project_id": "my-proj-1",
                "private_key_id": "abcd1234", "private_key": pem,
                "client_email": "sa@my-proj-1.iam.gserviceaccount.com",
                "token_uri": "https://token.example/t"}),
        ),
        (
            "azure_sp",
            "zk",
            json!({"tenant_id": g, "client_id": g, "client_secret": cs}),
        ),
    ];
    for (kind, name, body) in files {
        let f = d.path().join(format!("{name}.json"));
        fs::write(&f, body.to_string()).unwrap();
        let o = saiife(
            &d,
            &[
                "add",
                name,
                "--kind",
                kind,
                "--service",
                "s",
                "--from-file",
                f.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(o.status.code(), Some(0), "{kind}: {}", err(&o));
        // The key file's token_uri is dropped with a note.
        if kind == "gcp_sa" {
            assert!(String::from_utf8_lossy(&o.stdout).contains("token_uri is ignored"));
        }
    }
    let l = list_json(&d);
    let kinds: Vec<&str> = l["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["aws", "gcp_sa", "azure_sp"]);
    // A bad key id is refused by the daemon without echoing it.
    let f = d.path().join("bad.json");
    fs::write(
        &f,
        json!({"access_key_id": "nope-leaky", "secret_access_key": sk}).to_string(),
    )
    .unwrap();
    let o = saiife(
        &d,
        &[
            "add",
            "bad",
            "--kind",
            "aws",
            "--service",
            "s",
            "--from-file",
            f.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("access_key_id is not in the expected form"));
    // No value in any output, list output or record.
    let mut seen = String::from_utf8_lossy(&o.stderr).into_owned();
    seen.push_str(&l.to_string());
    for r in secret_records(&d) {
        seen.push_str(&r.to_string());
    }
    for v in [akid, sk, "TESTBODY", cs, "nope-leaky", "token.example"] {
        assert!(!seen.contains(v), "{v} leaked");
    }
}

#[test]
fn secret_add_oauth2_fields() {
    let d = admin();
    let secret = format!("cs-{}", "7a".repeat(10));
    let refresh = format!("rt-{}", "b4".repeat(10));
    let v =
        json!({"client_id": "cid", "client_secret": secret, "refresh_token": refresh}).to_string();
    let o = saiife(
        &d,
        &[
            "add",
            "sf",
            "--kind",
            "oauth2",
            "--service",
            "sf",
            "--from-env",
            "SV",
        ],
        &[("SV", &v)],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let l = list_json(&d);
    assert_eq!(l["secrets"][0]["name"], "sf");
    assert_eq!(l["secrets"][0]["kind"], "oauth2");
    // Not the three fields: refused by the CLI, without quoting the input.
    let bad = json!({"client_id": "cid", "refresh_token": refresh}).to_string();
    let o = saiife(
        &d,
        &[
            "add",
            "sf2",
            "--kind",
            "oauth2",
            "--service",
            "sf",
            "--from-env",
            "SV",
        ],
        &[("SV", &bad)],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("client_id, client_secret and refresh_token"));
    // A key twice: refused, though the object has three distinct keys.
    let dup = format!(
        r#"{{"client_id":"cid","client_secret":"{secret}","refresh_token":"{refresh}","refresh_token":"rt-dup-{}"}}"#,
        "d0".repeat(8)
    );
    let o = saiife(
        &d,
        &[
            "add",
            "sf3",
            "--kind",
            "oauth2",
            "--service",
            "sf",
            "--from-env",
            "SV",
        ],
        &[("SV", &dup)],
    );
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("client_id, client_secret and refresh_token"));
    assert!(!err(&o).contains(&refresh) && !err(&o).contains("rt-dup-"));
    // Rotate reads the same shape (the stored kind says so).
    let f = d.path().join("oauth.json");
    let refresh2 = format!("rt-{}", "c5".repeat(10));
    fs::write(
        &f,
        json!({"client_id": "cid", "client_secret": secret, "refresh_token": refresh2}).to_string(),
    )
    .unwrap();
    let o = saiife(
        &d,
        &["rotate", "sf", "--from-file", f.to_str().unwrap()],
        &[],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let mut hay = String::from_utf8_lossy(&o.stderr).into_owned();
    for e in fs::read_dir(d.audit_dir()).unwrap() {
        hay.push_str(&fs::read_to_string(e.unwrap().path()).unwrap_or_default());
    }
    for n in [&secret, &refresh, &refresh2] {
        assert!(!hay.contains(n.as_str()), "{n} leaked");
    }
}

#[test]
fn from_env_and_from_file() {
    let d = admin();
    // Two trailing newlines: only one is stripped, the other is a control
    // character, which the daemon refuses.
    let f = d.path().join("hdr.txt");
    fs::write(&f, "header-value-123\n\n").unwrap();
    let o = saiife(
        &d,
        &[
            "add",
            "hdr",
            "--kind",
            "header",
            "--service",
            "s",
            "--from-file",
            f.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(
        err(&o).contains("secret value has control characters"),
        "{}",
        err(&o)
    );
    // One trailing CRLF is stripped (a stored value with a CR would have
    // been refused above).
    fs::write(&f, "header-value-123\r\n").unwrap();
    let o = saiife(
        &d,
        &[
            "add",
            "hdr",
            "--kind",
            "header",
            "--service",
            "s",
            "--from-file",
            f.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    // basic, username:password split at the first colon.
    let o = saiife(
        &d,
        &[
            "add",
            "bas",
            "--kind",
            "basic",
            "--service",
            "s",
            "--from-env",
            "CRED",
        ],
        &[("CRED", "alice:pa:ss:word")],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let o = saiife(
        &d,
        &[
            "add",
            "bas2",
            "--kind",
            "basic",
            "--service",
            "s",
            "--from-env",
            "CRED",
        ],
        &[("CRED", "nocolonhere")],
    );
    assert_eq!(o.status.code(), Some(2));
    // Too short.
    let o = saiife(
        &d,
        &[
            "add",
            "tiny",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-env",
            "CRED",
        ],
        &[("CRED", "abc")],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("secret value is too short"), "{}", err(&o));
    // Unset variable, missing file, both sources.
    let o = saiife(
        &d,
        &[
            "add",
            "x1",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-env",
            "NOPE_UNSET",
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(2));
    let o = saiife(
        &d,
        &[
            "add",
            "x1",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-file",
            "/nonexistent/f",
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(2));
    let o = saiife(
        &d,
        &[
            "add",
            "x1",
            "--kind",
            "token",
            "--service",
            "s",
            "--from-file",
            "a",
            "--from-env",
            "B",
        ],
        &[],
    );
    assert_eq!(o.status.code(), Some(2));
    // No service.
    let o = saiife(
        &d,
        &["add", "x1", "--kind", "token", "--from-env", "CRED"],
        &[("CRED", "valuevalue")],
    );
    assert_eq!(o.status.code(), Some(2));
    let names: Vec<Value> = list_json(&d)["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("bas"), json!("hdr")]);
    // Rotating a basic secret reads username:password again.
    let o = saiife(
        &d,
        &["rotate", "bas", "--from-env", "CRED"],
        &[("CRED", "bob:newpassword")],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
}

#[test]
fn non_tty_without_source_refuses() {
    let d = admin();
    let o = saiife(&d, &["add", "k1", "--kind", "token", "--service", "s"], &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("needs a terminal"), "{}", err(&o));
    assert_eq!(list_json(&d)["secrets"], json!([]));
}

#[test]
fn daemon_down_exits_5() {
    let d = TestDaemon::prepare(&Opts::default());
    let o = saiife(&d, &["list"], &[]);
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
}
