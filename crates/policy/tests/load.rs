use saiife_policy::{load_system, Fail, Fsync, PolicyError};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/etc/config.toml")
}

/// A temp /etc/saiife with `config` as config.toml and the given drop-ins.
fn etc(config: &str, dropins: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    fs::write(&cfg, config).unwrap();
    if !dropins.is_empty() {
        fs::create_dir(dir.path().join("policy.d")).unwrap();
        for (name, text) in dropins {
            fs::write(dir.path().join("policy.d").join(name), text).unwrap();
        }
    }
    (dir, cfg)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[test]
fn spec_example_parses() {
    let p = load_system(&fixture()).unwrap();
    let c = &p.config;
    assert_eq!(c.version, 2);
    assert!(c.locked);
    assert_eq!(c.audit.checkpoint_every, 1000);
    assert_eq!(c.audit.checkpoint_interval, Duration::from_secs(900));
    assert_eq!(c.audit.min_free_mb, 512);
    assert_eq!(c.audit.fsync, Fsync::Checkpoint);
    assert!(c.audit.forward.contains_key("siem"));
    assert_eq!(c.daemon.user, "saiife");
    assert_eq!(c.scope.len(), 1);
    assert_eq!(c.scope[0].name, "shop-agent");
    assert_eq!(c.scope[0].users, vec!["agent-shop"]);
    assert_eq!(c.scope[0].env.as_deref(), Some("prod"));
    assert_eq!(c.guard.packs, vec!["db.postgres"]);
    assert_eq!(c.guard.ask, vec!["core.git/force-push"]);
    assert!(c.services.contains_key("shopify"));
    assert_eq!(c.example.len(), 2);
    assert_eq!(c.approval.timeout, Duration::from_secs(1800));
    assert_eq!(c.gateway.upstream_timeout, Duration::from_secs(30));
    assert_eq!(p.files.len(), 2);
    assert!(p.files[0].0.ends_with("config.toml"), "{:?}", p.files);
    assert!(p.files[1].0.ends_with("shopify.toml"), "{:?}", p.files);
    assert!(p.files.iter().all(|(_, h)| is_hex64(h)), "{:?}", p.files);
}

#[test]
fn defaults_when_sections_missing() {
    let (_d, cfg) = etc("version = 2\nlocked = true\n", &[]);
    let p = load_system(&cfg).unwrap();
    let c = &p.config;
    assert_eq!(c.audit.checkpoint_every, 1000);
    assert_eq!(c.audit.checkpoint_interval, Duration::from_secs(900));
    assert_eq!(c.audit.min_free_mb, 512);
    assert_eq!(c.audit.fsync, Fsync::Checkpoint);
    assert_eq!(c.audit.retention_months, 24);
    assert_eq!(c.audit.dir, PathBuf::from("/var/log/saiife/audit"));
    assert_eq!(c.daemon.user, "saiife");
    assert_eq!(c.daemon.socket_dir, PathBuf::from("/run/saiife"));
    assert_eq!(c.guard.budget_ms, 50);
    assert_eq!(c.guard.fail, Fail::Closed);
    assert_eq!(c.approval.timeout, Duration::from_secs(1800));
    assert_eq!(c.approval.grant_ttl, Duration::from_secs(900));
    assert_eq!(c.gateway.tcp, "");
    assert_eq!(c.gateway.max_response_bytes, 5_242_880);
    assert_eq!(c.gateway.upstream_timeout, Duration::from_secs(30));
    assert!(c.scope.is_empty() && c.services.is_empty());
    assert_eq!(p.files.len(), 1);
}

#[test]
fn unknown_key_is_error() {
    let (_d, cfg) = etc("version = 2\n[audit]\ncheckpoint_evry = 5\n", &[]);
    match load_system(&cfg) {
        Err(PolicyError::Parse { detail, .. }) => {
            assert!(detail.contains("checkpoint_evry"), "{detail}")
        }
        other => panic!("expected Parse, got {other:?}"),
    }
}

#[test]
fn bad_duration_is_error() {
    let (_d, cfg) = etc("version = 2\n[audit]\ncheckpoint_interval = \"0m\"\n", &[]);
    assert!(matches!(load_system(&cfg), Err(PolicyError::Parse { .. })));
}

#[test]
fn version_must_be_2() {
    for text in ["version = 1\n", "version = 3\n"] {
        let (_d, cfg) = etc(text, &[]);
        assert!(
            matches!(load_system(&cfg), Err(PolicyError::Invalid { .. })),
            "{text}"
        );
    }
    let (_d, cfg) = etc("locked = true\n", &[]);
    assert!(matches!(load_system(&cfg), Err(PolicyError::Parse { .. })));
}

#[test]
fn profile_is_reserved() {
    let (_d, cfg) = etc("version = 2\nprofile = \"x\"\n", &[]);
    match load_system(&cfg) {
        Err(PolicyError::Reserved { key, .. }) => assert!(key.contains("profile")),
        other => panic!("expected Reserved, got {other:?}"),
    }
    let (_d, cfg) = etc(
        "version = 2\n[[scope]]\nname = \"a\"\nprofile = \"x\"\n",
        &[],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Reserved { .. })
    ));
    // In a drop-in scope too.
    let (_d, cfg) = etc(
        "version = 2\n",
        &[("a.toml", "[[scope]]\nname = \"a\"\nprofile = \"x\"\n")],
    );
    let e = load_system(&cfg).unwrap_err();
    assert!(matches!(e, PolicyError::Reserved { .. }), "{e:?}");
    assert!(e.to_string().contains("reserved for v3"), "{e}");
}

#[test]
fn locked_forces_fail_closed() {
    let (_d, cfg) = etc(
        "version = 2\nlocked = true\n[guard]\nfail = \"open\"\n",
        &[],
    );
    let p = load_system(&cfg).unwrap();
    assert_eq!(p.config.guard.fail, Fail::Closed);
    assert!(!p.warnings.is_empty());
    let (_d, cfg) = etc("version = 2\n[guard]\nfail = \"open\"\n", &[]);
    assert_eq!(load_system(&cfg).unwrap().config.guard.fail, Fail::Open);
}

#[test]
fn dropins_join_guard_arrays_in_name_order() {
    let (_d, cfg) = etc(
        "version = 2\n[guard]\npacks = [\"db.postgres\"]\n",
        &[
            ("20-b.toml", "[guard]\npacks = [\"y\"]\n[guard.mcp]\nallow_servers = [\"s2\"]\n"),
            ("10-a.toml", "[guard]\npacks = [\"x\"]\nask = [\"a/b\"]\n[guard.mcp]\nallow_servers = [\"s1\"]\n"),
            ("notes.txt", "this is not toml ["),
        ],
    );
    let p = load_system(&cfg).unwrap();
    assert_eq!(p.config.guard.packs, vec!["db.postgres", "x", "y"]);
    assert_eq!(p.config.guard.ask, vec!["a/b"]);
    assert_eq!(p.config.guard.mcp.allow_servers, vec!["s1", "s2"]);
    let names: Vec<_> = p.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names.len(), 3);
    assert!(
        names[1].ends_with("10-a.toml") && names[2].ends_with("20-b.toml"),
        "{names:?}"
    );
}

#[test]
fn dropins_join_scopes_and_examples() {
    let (_d, cfg) = etc(
        "version = 2\n[[scope]]\nname = \"a\"\n",
        &[(
            "x.toml",
            "[[scope]]\nname = \"b\"\n[[example]]\nuser = \"u\"\n",
        )],
    );
    let p = load_system(&cfg).unwrap();
    let names: Vec<_> = p.config.scope.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(p.config.example.len(), 1);
}

#[test]
fn duplicate_scope_name_is_error() {
    let (_d, cfg) = etc(
        "version = 2\n[[scope]]\nname = \"a\"\n",
        &[("x.toml", "[[scope]]\nname = \"a\"\n")],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
}

#[test]
fn service_defined_twice_is_error() {
    let (_d, cfg) = etc(
        "version = 2\n",
        &[
            (
                "10-one.toml",
                "[services.shopify]\nconnector = \"shopify\"\n",
            ),
            (
                "20-two.toml",
                "[services.shopify]\nconnector = \"shopify\"\n",
            ),
        ],
    );
    let e = load_system(&cfg).unwrap_err();
    match &e {
        PolicyError::DuplicateService {
            name,
            first,
            second,
        } => {
            assert_eq!(name, "shopify");
            assert!(first.ends_with("10-one.toml"), "{first}");
            assert!(second.ends_with("20-two.toml"), "{second}");
        }
        other => panic!("expected DuplicateService, got {other:?}"),
    }
    let msg = e.to_string();
    assert!(
        msg.contains("10-one.toml") && msg.contains("20-two.toml"),
        "{msg}"
    );
}

#[test]
fn service_in_config_and_dropin_is_error() {
    let (_d, cfg) = etc(
        "version = 2\n[services.shopify]\nconnector = \"shopify\"\n",
        &[("x.toml", "[services.shopify]\nconnector = \"shopify\"\n")],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::DuplicateService { .. })
    ));
}

#[test]
fn dropin_cannot_set_daemon() {
    let (_d, cfg) = etc(
        "version = 2\n",
        &[("x.toml", "[daemon]\nuser = \"root\"\n")],
    );
    match load_system(&cfg) {
        Err(PolicyError::Invalid { path, detail }) => {
            assert!(path.ends_with("x.toml"), "{path:?}");
            assert_eq!(detail, "daemon may only be set in config.toml");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    for (text, key) in [
        ("locked = false\n", "locked"),
        ("[guard]\nfail = \"open\"\n", "guard.fail"),
        ("[guard]\nbudget_ms = 1\n", "guard.budget_ms"),
        ("[audit]\nmin_free_mb = 1\n", "audit"),
    ] {
        let (_d, cfg) = etc("version = 2\n", &[("x.toml", text)]);
        match load_system(&cfg) {
            Err(PolicyError::Invalid { detail, .. }) => {
                assert_eq!(detail, format!("{key} may only be set in config.toml"))
            }
            other => panic!("{text}: expected Invalid, got {other:?}"),
        }
    }
}

#[test]
fn dropin_unknown_key_is_parse_error() {
    let (_d, cfg) = etc("version = 2\n", &[("x.toml", "[guard]\npaks = [\"x\"]\n")]);
    match load_system(&cfg) {
        Err(PolicyError::Parse { detail, .. }) => assert!(detail.contains("paks"), "{detail}"),
        other => panic!("expected Parse, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn symlinked_dropin_is_refused() {
    let (d, cfg) = etc("version = 2\n", &[("a.toml", "[guard]\npacks = [\"x\"]\n")]);
    let target = d.path().join("elsewhere.toml");
    fs::write(&target, "[guard]\npacks = [\"evil\"]\n").unwrap();
    std::os::unix::fs::symlink(&target, d.path().join("policy.d/b.toml")).unwrap();
    match load_system(&cfg) {
        Err(PolicyError::Invalid { path, .. }) => assert!(path.ends_with("b.toml"), "{path:?}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn directory_named_toml_is_refused() {
    let (d, cfg) = etc("version = 2\n", &[("a.toml", "")]);
    fs::create_dir(d.path().join("policy.d/sub.toml")).unwrap();
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
}

#[test]
fn oversized_file_is_refused() {
    let big = format!("version = 2\n#{}\n", "x".repeat(1024 * 1024));
    let (_d, cfg) = etc(&big, &[]);
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
}

#[test]
fn missing_config_is_io_error() {
    let d = tempfile::tempdir().unwrap();
    assert!(matches!(
        load_system(&d.path().join("config.toml")),
        Err(PolicyError::Io { .. })
    ));
}

/// Editor droppings (`.#a.toml` emacs lock links, `.a.toml.swp`-style
/// hidden files) are skipped, not loaded and not refused (M3).
#[cfg(unix)]
#[test]
fn dotfiles_in_policy_d_are_skipped() {
    let (d, cfg) = etc(
        "version = 2\n",
        &[
            ("a.toml", "[guard]\npacks = [\"x\"]\n"),
            (".hidden.toml", "not toml at all ["),
        ],
    );
    std::os::unix::fs::symlink(
        "jonas@host.1234:1700000000",
        d.path().join("policy.d/.#a.toml"),
    )
    .unwrap();
    let l = load_system(&cfg).unwrap();
    assert_eq!(l.files.len(), 2, "{:?}", l.files);
    assert!(
        l.files.iter().all(|(n, _)| !n.contains("policy.d/.")),
        "{:?}",
        l.files
    );
}

/// A symlinked `policy.d` is refused like a symlinked drop-in (M3).
#[cfg(unix)]
#[test]
fn symlinked_policy_d_is_refused() {
    let (d, cfg) = etc("version = 2\n", &[]);
    let real = d.path().join("elsewhere");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("a.toml"), "[guard]\npacks = [\"evil\"]\n").unwrap();
    std::os::unix::fs::symlink(&real, d.path().join("policy.d")).unwrap();
    match load_system(&cfg) {
        Err(PolicyError::Invalid { path, .. }) => assert!(path.ends_with("policy.d"), "{path:?}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn typed_services_reject_unknown_key() {
    let (_d, cfg) = etc(
        "version = 2\n",
        &[(
            "10-shop.toml",
            "[services.shopify]\nconnector = \"shopify\"\nallwo = []\n",
        )],
    );
    let e = load_system(&cfg).unwrap_err();
    let msg = e.to_string();
    assert!(matches!(e, PolicyError::Parse { .. }), "{msg}");
    assert!(
        msg.contains("allwo") && msg.contains("10-shop.toml"),
        "{msg}"
    );
    // Nested typed tables too.
    let (_d, cfg) = etc(
        "version = 2\n[services.s]\nconnector = \"c\"\n[services.s.limits]\nrequests_per_min = 1\n",
        &[],
    );
    let msg = load_system(&cfg).unwrap_err().to_string();
    assert!(
        msg.contains("requests_per_min") && msg.contains("config.toml"),
        "{msg}"
    );
}

#[test]
fn profile_key_reserved() {
    for text in [
        "version = 2\n[services.s]\nconnector = \"c\"\nprofile = \"x\"\n",
        "version = 2\n[services.s]\nconnector = \"c\"\n[services.s.limits]\nprofile = 1\n",
        "version = 2\n[services.s]\nconnector = \"c\"\n[[services.s.rule]]\ncapability = \"a:read\"\naction = \"allow\"\nprofile = \"x\"\n",
        "version = 2\n[secrets.k]\nprofile = \"x\"\n",
    ] {
        let (_d, cfg) = etc(text, &[]);
        let e = load_system(&cfg).unwrap_err();
        assert!(matches!(e, PolicyError::Reserved { .. }), "{text}: {e:?}");
        assert!(e.to_string().contains("reserved for v3"), "{e}");
    }
    let (_d, cfg) = etc(
        "version = 2\n",
        &[(
            "a.toml",
            "[services.s]\nconnector = \"c\"\nprofile = \"x\"\n",
        )],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Reserved { .. })
    ));
}

#[test]
fn run_allow_refuses_interpreters() {
    for bad in [
        "/usr/bin/python3",
        "/usr/bin/python3.12",
        "/bin/sh",
        "/usr/bin/env",
        "/usr/bin/osascript",
        "/bin/busybox",
    ] {
        let (_d, cfg) = etc(
            &format!("version = 2\n[secrets.k]\nrun_allow = [\"/usr/bin/curl\", \"{bad}\"]\n"),
            &[],
        );
        let e = load_system(&cfg).unwrap_err();
        assert!(
            matches!(&e, PolicyError::RunAllowInterpreter { secret, .. } if secret == "k"),
            "{bad}: {e:?}"
        );
    }
    // A drop-in is checked too.
    let (_d, cfg) = etc(
        "version = 2\n",
        &[("a.toml", "[secrets.k]\nrun_allow = [\"/usr/bin/node\"]\n")],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::RunAllowInterpreter { .. })
    ));
    let (_d, cfg) = etc(
        "version = 2\n[secrets.k]\nrun_allow = [\"/usr/bin/curl\", \"/opt/tools/python-lint\"]\n",
        &[],
    );
    let c = load_system(&cfg).unwrap().config;
    assert_eq!(c.secrets["k"].run_allow.len(), 2);
}

#[test]
fn secret_defined_twice_and_bad_auth_kind() {
    let (_d, cfg) = etc(
        "version = 2\n[secrets.k]\nrun_allow = []\n",
        &[("a.toml", "[secrets.k]\nrun_allow = []\n")],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
    let (_d, cfg) = etc(
        "version = 2\n[services.s]\nconnector = \"c\"\nauth = { kind = \"magic\" }\n",
        &[],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
}

#[test]
fn spec_shopify_dropin_types() {
    let (_d, cfg) = etc(
        "version = 2\n",
        &[(
            "shopify.toml",
            "[services.shopify]\nconnector = \"shopify\"\nsecret = \"shopify-prod\"\nparams = { shop = \"acme\" }\n\
             allow = [\"orders:read\"]\ndeny = [\"*:delete\"]\n\
             [services.shopify.limits]\nrequests_per_minute = 60\namount_per_day = { max = 500, currency = \"EUR\" }\n\
             [services.shopify.redact]\nfields = [\"customer.email\"]\n",
        )],
    );
    let c = load_system(&cfg).unwrap().config;
    let s = &c.services["shopify"];
    assert_eq!(s.params["shop"], "acme");
    assert_eq!(s.limits.requests_per_minute, Some(60));
    assert_eq!(s.limits.amount_per_day.as_ref().unwrap().max, 500);
    assert_eq!(s.redact.fields, vec!["customer.email"]);
}

#[test]
fn patterns_are_validated_at_load() {
    for (field, pat) in [
        ("deny", "customers:exprot"),
        ("allow", "orders"),
        ("ask", "Orders:read"),
        ("allow", "*"),
        ("deny", "orders:read:"),
    ] {
        let (_d, cfg) = etc(
            "version = 2\n",
            &[(
                "10-s.toml",
                &format!("[services.s]\nconnector = \"c\"\n{field} = [\"{pat}\"]\n"),
            )],
        );
        let e = load_system(&cfg).unwrap_err();
        let msg = e.to_string();
        assert!(matches!(e, PolicyError::Invalid { .. }), "{pat}: {msg}");
        assert!(msg.contains("10-s.toml") && msg.contains(pat), "{msg}");
    }
    let (_d, cfg) = etc(
        "version = 2\n[services.s]\nconnector = \"c\"\n[[services.s.rule]]\ncapability = \"issues:wirte\"\naction = \"deny\"\n",
        &[],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Invalid { .. })
    ));
}

#[test]
fn profile_as_param_name_is_fine() {
    let (_d, cfg) = etc(
        "version = 2\n[services.s]\nconnector = \"c\"\nparams = { profile = \"p\" }\nfixed = { profile = \"q\" }\n",
        &[],
    );
    let c = load_system(&cfg).unwrap().config;
    assert_eq!(c.services["s"].params["profile"], "p");
    // A service named like a map is still checked.
    let (_d, cfg) = etc(
        "version = 2\n[services.params]\nconnector = \"c\"\nprofile = \"x\"\n",
        &[],
    );
    assert!(matches!(
        load_system(&cfg),
        Err(PolicyError::Reserved { .. })
    ));
}

#[test]
fn run_allow_hardening() {
    for bad in [
        "/usr/bin/python2",
        "/usr/bin/ruby3.2",
        "/usr/bin/perl5.36",
        "/usr/bin/lua5.4",
        "/usr/bin/php8.2",
        "/usr/bin/python3.12",
        "/usr/bin/nodejs",
        "/usr/bin/pypy3",
        "/usr/bin/pypy",
        "/bin/BASH",
        "/bin/Python3",
    ] {
        let (_d, cfg) = etc(
            &format!("version = 2\n[secrets.k]\nrun_allow = [\"{bad}\"]\n"),
            &[],
        );
        assert!(
            matches!(
                load_system(&cfg),
                Err(PolicyError::RunAllowInterpreter { .. })
            ),
            "{bad}"
        );
    }
    let (_d, cfg) = etc("version = 2\n[secrets.k]\nrun_allow = [\"curl\"]\n", &[]);
    let e = load_system(&cfg).unwrap_err();
    assert!(e.to_string().contains("absolute"), "{e}");
}
