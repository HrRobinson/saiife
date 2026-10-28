//! `saiife connect <service>` against a real daemon on temp dirs (plan 10,
//! Task 15). The daemon runs as the test user; admin ops authorize through
//! `[admin] groups = [<primary group>]`.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, Opts, TestDaemon};
use saiife_broker::catalog::{validate, Catalog};
use saiife_broker::manifest::builtin;
use saiife_policy::{decide, load_system, Capability, Mode, Request, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

const TOKEN: &str = "shpat_connect_test_value_123";

fn admin() -> TestDaemon {
    TestDaemon::start(Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    })
}

fn connect(d: &TestDaemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("connect")
        .args(args)
        .arg("--config")
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .env("CONNECT_TEST_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn secrets(d: &TestDaemon) -> Vec<String> {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["secret", "list", "--json", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect()
}

fn policy_file(d: &TestDaemon, name: &str) -> std::path::PathBuf {
    d.path().join("etc/policy.d").join(name)
}

#[test]
fn generated_file_denies_everything() {
    let d = admin();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert!(o.status.success(), "{}", err(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    let path = policy_file(&d, "shopify.toml");
    assert!(
        out.contains(&format!(
            "next: edit {}, then saiife policy reload",
            path.display()
        )),
        "{out}"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(secrets(&d), vec!["shopify".to_string()]);

    let text = fs::read_to_string(&path).unwrap();
    for h in ["# allow = [", "# ask = [", "# deny = ["] {
        assert!(text.contains(h), "{h}");
    }
    assert!(text.contains("# refunds.create write"), "{text}");
    assert!(!text.contains(TOKEN));
    // No active list.
    assert!(!text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("allow") || l.starts_with("ask") || l.starts_with("deny")
    }));

    let loaded = load_system(&d.config()).expect("loads");
    let cat = Catalog::new(builtin(), vec![]);
    validate(&loaded.config, &cat).expect("validates");
    let svc = &loaded.config.services["shopify"];
    assert_eq!(svc.params["shop"], "acme");
    assert_eq!(svc.secret.as_deref(), Some("shopify"));
    let m = builtin().iter().find(|m| m.id == "shopify").unwrap();
    assert!(!m.operation.is_empty());
    for o in &m.operation {
        let cap = Capability::parse(&o.capability).unwrap();
        let params = BTreeMap::new();
        let v = decide(
            svc,
            None,
            Mode::Locked,
            &Request {
                capability: &cap,
                params: &params,
            },
        );
        assert_eq!(
            v,
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{}",
            o.id
        );
    }
}

#[test]
fn existing_file_refused() {
    let d = admin();
    fs::create_dir_all(d.path().join("etc/policy.d")).unwrap();
    let p = policy_file(&d, "shopify.toml");
    fs::write(&p, "# mine\n").unwrap();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("policy.d/shopify.toml exists; edit it"),
        "{}",
        err(&o)
    );
    assert_eq!(fs::read_to_string(&p).unwrap(), "# mine\n");
    assert!(secrets(&d).is_empty(), "nothing is stored");
}

#[test]
fn unknown_connector_refused() {
    let d = admin();
    let o = connect(&d, &["nope", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("unknown connector nope"), "{}", err(&o));

    let o = connect(
        &d,
        &[
            "web",
            "--connector",
            "http",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("the http connector is configured by hand: see docs/connectors/http.md"),
        "{}",
        err(&o)
    );
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "nope.toml").exists());
    assert!(!policy_file(&d, "web.toml").exists());
}

#[test]
fn required_param_prompted_or_refused() {
    let d = admin();
    // No terminal: refused by name.
    let o = connect(&d, &["shopify", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("missing --param shop"), "{}", err(&o));
    // A value that fails the manifest pattern.
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=Bad Shop",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("--param shop"), "{}", err(&o));
    // A parameter the manifest does not declare.
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "x=1",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "shopify.toml").exists());
    // GitHub has no required parameter: no prompt, no refusal.
    let o = connect(&d, &["github", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(policy_file(&d, "github.toml").exists());
}

#[test]
fn unwritable_policy_dir_stores_nothing() {
    let d = admin();
    let dir = d.path().join("etc/policy.d");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(secrets(&d).is_empty());
}

fn add_secret(d: &TestDaemon, name: &str, service: &str) {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args([
            "secret",
            "add",
            name,
            "--kind",
            "token",
            "--service",
            service,
        ])
        .args(["--from-env", "CONNECT_TEST_TOKEN", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("CONNECT_TEST_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn existing_secret_is_reused_when_it_allows_the_service() {
    let d = admin();
    add_secret(&d, "imported", "shopify");
    let o = connect(
        &d,
        &["shopify", "--param", "shop=acme", "--secret", "imported"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(secrets(&d), vec!["imported".to_string()]);
    let text = fs::read_to_string(policy_file(&d, "shopify.toml")).unwrap();
    assert!(text.contains("secret = \"imported\""), "{text}");
}

#[test]
fn existing_secret_for_another_service_is_refused() {
    let d = admin();
    add_secret(&d, "imported", "github");
    let o = connect(
        &d,
        &["shopify", "--param", "shop=acme", "--secret", "imported"],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("secret imported exists but does not allow shopify; use another name"),
        "{}",
        err(&o)
    );
    assert!(!policy_file(&d, "shopify.toml").exists());
}

#[test]
fn salesforce_connect_stores_an_oauth2_secret() {
    let d = admin();
    // Built at runtime: no token-shaped literal in the source.
    let refresh = format!("5Aep{}", "x7".repeat(20));
    let secret = format!("cs-{}", "q4".repeat(16));
    let value = serde_json::json!({
        "client_id": "3MVG9connect.test",
        "client_secret": secret,
        "refresh_token": refresh,
    })
    .to_string();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args([
            "connect",
            "salesforce",
            "--param",
            "instance_host=acme.my.salesforce.com",
            "--param",
            "api_version=v60.0",
            "--from-env",
            "CONNECT_TEST_OAUTH",
            "--config",
        ])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .env("CONNECT_TEST_OAUTH", &value)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let printed = format!("{}{}", err(&o), String::from_utf8_lossy(&o.stdout));
    for needle in [&refresh, &secret] {
        assert!(!printed.contains(needle.as_str()));
    }

    let l = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["secret", "list", "--json", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(l.status.success(), "{}", err(&l));
    let v: Value = serde_json::from_slice(&l.stdout).unwrap();
    let s = &v["secrets"][0];
    assert_eq!(s["name"], "salesforce");
    assert_eq!(s["kind"], "oauth2");

    let text = fs::read_to_string(policy_file(&d, "salesforce.toml")).unwrap();
    assert!(!text.contains(&refresh) && !text.contains(&secret));
    let loaded = load_system(&d.config()).expect("loads");
    validate(&loaded.config, &Catalog::new(builtin(), vec![])).expect("validates");
}

/// A cloud secret file's JSON for the vault kind `kind`, built at runtime
/// so no token-shaped literal is in the source.
fn cloud_secret_json(kind: &str) -> String {
    let akid = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    let guid = "0123abcd-4567-89ab-cdef-0123456789ab";
    let pem = [
        "-----BEGIN ",
        "PRIVATE KEY-----\nTESTBODYTESTBODY0001\n-----END ",
        "PRIVATE KEY-----\n",
    ]
    .concat();
    match kind {
        "aws" => serde_json::json!({
            "access_key_id": akid,
            "secret_access_key": format!("sk-{}", "k9".repeat(18)),
        }),
        "azure_sp" => serde_json::json!({
            "tenant_id": guid, "client_id": guid,
            "client_secret": format!("cs-{}", "z3".repeat(12)),
        }),
        "gcp_sa" => serde_json::json!({
            "client_email": "sa@p.iam.gserviceaccount.com",
            "private_key": pem,
            "private_key_id": "abcd1234",
        }),
        _ => unreachable!(),
    }
    .to_string()
}

fn vault_kind(auth: &str) -> Option<&'static str> {
    match auth {
        "aws_sigv4" => Some("aws"),
        "gcp_sa" => Some("gcp_sa"),
        "azure_sp" => Some("azure_sp"),
        _ => None,
    }
}

fn secret_kinds(d: &TestDaemon) -> BTreeMap<String, String> {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["secret", "list", "--json", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["name"].as_str().unwrap().to_string(),
                s["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn connect_aws_writes_commented_sts_block() {
    let d = admin();
    let file = d.path().join("aws.json");
    fs::write(&file, cloud_secret_json("aws")).unwrap();
    let o = connect(
        &d,
        &[
            "aws-s3",
            "--param",
            "region=eu-west-1",
            "--from-file",
            file.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(secret_kinds(&d)["aws-s3"], "aws");
    let text = fs::read_to_string(policy_file(&d, "aws-s3.toml")).unwrap();
    for line in [
        "# mode = \"sts\"",
        "# [services.aws-s3.cloud]",
        "# role_arn = ",
        "# run_allow = ",
        "docs/connectors/aws-s3.md",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    // Every STS line is a comment: the service stays in sign mode.
    let loaded = load_system(&d.config()).expect("loads");
    assert_eq!(
        loaded.config.services["aws-s3"].mode,
        saiife_policy::CloudMode::Sign
    );
    assert!(!text.contains("IOSFODNN7EXAMPLE"));
}

#[test]
fn connect_gcp_needs_from_file() {
    let d = admin();
    for extra in [&[][..], &["--from-env", "CONNECT_TEST_TOKEN"][..]] {
        let mut args = vec!["gcp-storage"];
        args.extend_from_slice(extra);
        let o = connect(&d, &args);
        assert_eq!(o.status.code(), Some(2));
        assert!(err(&o).contains("--from-file"), "{}", err(&o));
    }
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "gcp-storage.toml").exists());
    let file = d.path().join("sa.json");
    fs::write(&file, cloud_secret_json("gcp_sa")).unwrap();
    let o = connect(&d, &["gcp-storage", "--from-file", file.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(secret_kinds(&d)["gcp-storage"], "gcp_sa");
}

/// A value that passes the manifest's own check for each required param.
fn test_params(m: &saiife_broker::manifest::Manifest) -> Vec<String> {
    const TRIES: [&str; 10] = [
        "acme.example.com",
        "acme",
        "api.intercom.io",
        "api.segment.io",
        "2.10",
        "v60.0",
        "USD",
        "ops@example.com",
        "acme.my.salesforce.com",
        "eu-west-1",
    ];
    let mut out = Vec::new();
    for (name, spec) in &m.params {
        if !spec.required {
            continue;
        }
        let ty = spec.param_type().unwrap();
        let v = TRIES
            .iter()
            .find(|v| ty.check(v).is_ok())
            .unwrap_or_else(|| panic!("{}.{name}: no test value fits", m.id));
        out.push("--param".to_string());
        out.push(format!("{name}={v}"));
    }
    out
}

#[test]
fn connect_every_builtin_generates_deny_all() {
    let d = admin();
    // Built at runtime: no token-shaped literal in the source.
    let oauth = serde_json::json!({
        "client_id": "cid-connect-test",
        "client_secret": format!("cs-{}", "q4".repeat(16)),
        "refresh_token": format!("rt-{}", "x7".repeat(20)),
    })
    .to_string();
    let basic = format!("user:{}", "pw".repeat(8));
    for m in builtin() {
        let value = match m.auth.first().map(|a| a.kind.as_str()) {
            Some("basic") => basic.clone(),
            Some("oauth2") => oauth.clone(),
            _ => TOKEN.to_string(),
        };
        let mut args = vec![m.id.as_str()];
        let given = test_params(m);
        args.extend(given.iter().map(String::as_str));
        let file = d.path().join(format!("{}.secret.json", m.id));
        let kind = m.auth.first().and_then(|a| vault_kind(&a.kind));
        match kind {
            Some(k) => {
                fs::write(&file, cloud_secret_json(k)).unwrap();
                args.extend(["--from-file", file.to_str().unwrap()]);
            }
            None => args.extend(["--from-env", "CONNECT_TEST_VALUE"]),
        }
        let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
            .arg("connect")
            .args(&args)
            .arg("--config")
            .arg(d.config())
            .env("HOME", d.path().join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", d.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", d.audit_dir())
            .env("CONNECT_TEST_VALUE", &value)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(o.status.success(), "{}: {}", m.id, err(&o));

        let loaded = load_system(&d.config()).unwrap_or_else(|e| panic!("{}: {e:?}", m.id));
        validate(&loaded.config, &Catalog::new(builtin(), vec![]))
            .unwrap_or_else(|e| panic!("{}: {e}", m.id));
        let svc = &loaded.config.services[m.id.as_str()];
        assert!(!m.operation.is_empty());
        for o in &m.operation {
            let cap = Capability::parse(&o.capability).unwrap();
            let params = BTreeMap::new();
            let v = decide(
                svc,
                None,
                Mode::Locked,
                &Request {
                    capability: &cap,
                    params: &params,
                },
            );
            assert_eq!(
                v,
                Verdict::Deny {
                    rule: "default_deny".into()
                },
                "{}.{}",
                m.id,
                o.id
            );
        }
    }
    let listed = secrets(&d);
    for m in builtin() {
        assert!(listed.contains(&m.id), "{} has no secret", m.id);
    }
}

#[test]
fn connect_refuses_a_host_param_that_is_not_a_hostname() {
    let d = admin();
    // The pattern allows `localhost`; the host rule of `policy check` does not.
    let o = connect(
        &d,
        &[
            "email",
            "--param",
            "smtp_host=localhost",
            "--param",
            "imap_host=imap.example.com",
            "--param",
            "from=ops@example.com",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("--param smtp_host: not a bare lower-case hostname"),
        "{}",
        err(&o)
    );
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "email.toml").exists());
}

#[test]
fn connect_salesforce_prompts_oauth2_fields() {
    let d = admin();
    let base = [
        "salesforce",
        "--param",
        "instance_host=acme.my.salesforce.com",
        "--param",
        "api_version=v60.0",
    ];
    // No source and no terminal: the paste flow needs a terminal.
    let o = connect(&d, &base);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("needs a terminal"), "{}", err(&o));
    // A JSON object that lacks a field is refused by name, without quoting it.
    let partial = r#"{"client_id":"cid-connect-test","client_secret":"aaaaaaaaaaaaaaaa"}"#;
    let mut args = base.to_vec();
    args.extend(["--from-env", "CONNECT_TEST_PARTIAL"]);
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("connect")
        .args(&args)
        .arg("--config")
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .env("CONNECT_TEST_PARTIAL", partial)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("client_id, client_secret and refresh_token"),
        "{}",
        err(&o)
    );
    assert!(!err(&o).contains("aaaaaaaaaaaaaaaa"));
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "salesforce.toml").exists());
}
