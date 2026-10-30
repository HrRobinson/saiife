use saiife_policy::{load_system, Fail, Fsync, PolicyError, SystemConfig};
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
            "[[scope]]\nname = \"b\"\n[[example]]\nuser = \"u\"\ncommand = \"ls\"\nexpect = \"allow\"\n",
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
        "/usr/bin/ash",
        "/usr/bin/mksh",
        "/usr/bin/rbash",
        "/usr/bin/pwsh",
        "/usr/bin/awk",
        "/usr/bin/gawk",
        "/usr/bin/mawk",
        "/usr/bin/nawk",
        "/usr/bin/xargs",
        "/usr/bin/find",
        "/usr/bin/timeout",
        "/usr/bin/nice",
        "/usr/bin/nohup",
        "/usr/bin/stdbuf",
        "/usr/bin/setsid",
        "/usr/bin/sudo",
        "/usr/bin/doas",
        "/usr/sbin/chroot",
        "/usr/bin/irb",
        "/usr/bin/java",
        "/usr/bin/jshell",
        "/usr/bin/Rscript",
        "/usr/bin/expect",
        "/usr/bin/wish",
        "/usr/bin/vim",
        "/usr/bin/vi",
        "/usr/bin/ed",
        "/usr/bin/gdb",
        "/usr/bin/make",
        "/usr/bin/coreutils",
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
        "version = 2\n[secrets.k]\nrun_allow = [\"/usr/bin/curl\", \"/opt/tools/pylint-wrapper\"]\n",
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
        "/usr/bin/pythonw",
        "/usr/bin/ipython",
        "/usr/bin/python3m",
        "/usr/bin/perl-5.36",
        "/usr/bin/python-config",
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

#[test]
fn non_loopback_tcp_is_config_error_at_load() {
    let (_d, cfg) = etc(
        "version = 2\nlocked = true\n[gateway]\ntcp = \"0.0.0.0:7431\"\n",
        &[],
    );
    let e = load_system(&cfg).unwrap_err().to_string();
    assert!(e.contains("loopback"), "{e}");
    let (_d, cfg) = etc(
        "version = 2\nlocked = true\n[gateway]\ntcp = \"127.0.0.1:0\"\n",
        &[],
    );
    let p = load_system(&cfg).unwrap();
    assert_eq!(p.config.gateway.tcp_addr().unwrap().unwrap().port(), 0);
}

#[test]
fn approvers_are_validated() {
    let (_d, cfg) = etc(
        "version = 2\n[approval]\napprovers = [\"alice\", \"group:ops\"]\n",
        &[],
    );
    let p = load_system(&cfg).unwrap();
    assert_eq!(p.config.approval.approvers, vec!["alice", "group:ops"]);
    assert!(p.warnings.is_empty(), "{:?}", p.warnings);

    for bad in ["\"group:\"", "\"a b\"", "\"-x\"", "\"\""] {
        let (_d, cfg) = etc(
            &format!("version = 2\n[approval]\napprovers = [{bad}]\n"),
            &[],
        );
        match load_system(&cfg) {
            Err(PolicyError::Invalid { detail, .. }) => {
                assert!(detail.contains("approvers"), "{bad}: {detail}")
            }
            other => panic!("{bad}: expected Invalid, got {other:?}"),
        }
    }
}

#[test]
fn empty_approvers_with_ask_warns() {
    // No ask rules: nothing to approve, no warning.
    let (_d, cfg) = etc("version = 2\n", &[]);
    assert!(load_system(&cfg).unwrap().warnings.is_empty());
    let (_d, cfg) = etc(
        "version = 2\n[guard]\nask = [\"core.git/force-push\"]\n[approval]\napprovers = []\n",
        &[],
    );
    let p = load_system(&cfg).unwrap();
    assert!(p.config.approval.approvers.is_empty());
    assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
    assert!(
        p.warnings[0].contains("approvers is empty: nobody can approve"),
        "{:?}",
        p.warnings
    );
}

#[test]
fn guard_ask_entries_are_pack_slash_rule() {
    for bad in [
        "\"core.git\"",
        "\"/force-push\"",
        "\"core.git/\"",
        "\"a/b/c\"",
    ] {
        let (_d, cfg) = etc(&format!("version = 2\n[guard]\nask = [{bad}]\n"), &[]);
        match load_system(&cfg) {
            Err(PolicyError::Invalid { detail, .. }) => {
                assert!(detail.contains("[guard] ask entry"), "{bad}: {detail}")
            }
            other => panic!("{bad}: expected Invalid, got {other:?}"),
        }
    }
}

#[test]
fn unknown_guard_ask_rule_is_config_error() {
    use saiife_policy::{check_guard_ask, PackInfo};
    let pack = |id: &str, default_on, rules: &[&str]| PackInfo {
        id: id.into(),
        version: 1,
        default_on,
        rules: rules.iter().map(|r| r.to_string()).collect(),
    };
    let catalog = [
        pack("core.git", true, &["force-push", "reset-hard"]),
        pack("db.postgres", false, &["drop-database"]),
    ];
    let cfg_with = |extra: &str| {
        let (_d, cfg) = etc(&format!("version = 2\n[guard]\n{extra}\n"), &[]);
        load_system(&cfg).unwrap().config
    };
    let ok = cfg_with("ask = [\"core.git/force-push\"]");
    assert_eq!(check_guard_ask(&ok, &catalog), Ok(()));
    let e = check_guard_ask(&cfg_with("ask = [\"core.git/no-such\"]"), &catalog).unwrap_err();
    assert!(
        e.contains("core.git/no-such") && e.contains("no rule"),
        "{e}"
    );
    // A pack that exists but is not active.
    let e =
        check_guard_ask(&cfg_with("ask = [\"db.postgres/drop-database\"]"), &catalog).unwrap_err();
    assert!(e.contains("not active"), "{e}");
    let on = cfg_with("packs = [\"db.postgres\"]\nask = [\"db.postgres/drop-database\"]");
    assert_eq!(check_guard_ask(&on, &catalog), Ok(()));
    // No ask: nothing to check.
    assert_eq!(check_guard_ask(&cfg_with(""), &[]), Ok(()));
}

#[test]
fn http_forward_target_is_invalid() {
    let (_d, cfg) = etc(
        "version = 2\n[audit.forward.a]\ntype = \"https\"\nurl = \"http://h.test/\"\n",
        &[],
    );
    match load_system(&cfg) {
        Err(PolicyError::Invalid { detail, .. }) => {
            assert!(detail.contains("audit.forward.a"), "{detail}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

// ---- plan 15: cloud mode and [services.*.cloud] ----

const ROLE: &str = "arn:aws:iam::123456789012:role/saiife-run";

fn svc_cfg(extra: &str) -> Result<saiife_policy::LoadedPolicy, PolicyError> {
    let (_d, cfg) = etc(
        &format!("version = 2\n[services.s3]\nconnector = \"aws-s3\"\n{extra}"),
        &[],
    );
    load_system(&cfg)
}

fn refused(extra: &str) -> String {
    svc_cfg(extra).unwrap_err().to_string()
}

#[test]
fn mode_defaults_to_sign() {
    let p = svc_cfg("").unwrap();
    let s = &p.config.services["s3"];
    assert_eq!(s.mode, saiife_policy::CloudMode::Sign);
    assert_eq!(s.cloud, saiife_policy::CloudCfg::default());
    assert!(toml::from_str::<SystemConfig>(
        "version = 2\n[services.a]\nconnector = \"x\"\nmode = \"Sts\"\n"
    )
    .is_err());
}

#[test]
fn sts_needs_role_arn_and_run_allow() {
    assert!(refused("mode = \"sts\"\n").contains("role_arn"));
    let only_role = format!("mode = \"sts\"\n[services.s3.cloud]\nrole_arn = \"{ROLE}\"\n");
    assert!(refused(&only_role).contains("run_allow"));
    let only_run = "mode = \"sts\"\n[services.s3.cloud]\nrun_allow = [\"/usr/bin/aws\"]\n";
    assert!(refused(only_run).contains("role_arn"));
    let ok = format!(
        "mode = \"sts\"\n[services.s3.cloud]\nrole_arn = \"{ROLE}\"\nrun_allow = [\"/usr/bin/aws\"]\n"
    );
    let p = svc_cfg(&ok).unwrap();
    assert_eq!(p.config.services["s3"].mode, saiife_policy::CloudMode::Sts);
}

#[test]
fn bad_role_arn_refused() {
    for bad in [
        "arn:aws:iam::12345:role/x",
        "arn:aws:iam::123456789012:user/x",
        "arn:aws:iam::123456789012:role/",
        "arn:aws:s3:::123456789012:role/x",
        "arn:aws-x:iam::123456789012:role/x",
        "arn:aws:iam::123456789012:role/a b",
        "arn:aws:iam::123456789012:role/a\n",
    ] {
        let e = refused(&format!("[services.s3.cloud]\nrole_arn = {bad:?}\n"));
        assert!(e.contains("role_arn"), "{bad}: {e}");
    }
    for good in [
        ROLE,
        "arn:aws-cn:iam::123456789012:role/path/x_y+z=1,2.@-",
        "arn:aws-us-gov:iam::123456789012:role/x",
    ] {
        svc_cfg(&format!("[services.s3.cloud]\nrole_arn = {good:?}\n")).unwrap();
    }
    let long = format!("arn:aws:iam::123456789012:role/{}", "a".repeat(513));
    assert!(refused(&format!("[services.s3.cloud]\nrole_arn = {long:?}\n")).contains("role_arn"));
    for bad in ["a", "has space", "semi;colon"] {
        let e = refused(&format!("[services.s3.cloud]\nexternal_id = {bad:?}\n"));
        assert!(e.contains("external_id"), "{bad}: {e}");
    }
    svc_cfg("[services.s3.cloud]\nexternal_id = \"ab:c/d@e\"\n").unwrap();
}

#[test]
fn run_allow_interpreter_refused_in_cloud() {
    let e = refused("[services.s3.cloud]\nrun_allow = [\"/usr/bin/aws\", \"/bin/bash\"]\n");
    assert!(e.contains("interpreter") && e.contains("bash"), "{e}");
    let e = refused("[services.s3.cloud]\nrun_allow = [\"aws\"]\n");
    assert!(e.contains("absolute"), "{e}");
}

#[test]
fn authority_host_allowlist() {
    for ok in [
        "login.microsoftonline.com",
        "login.microsoftonline.us",
        "login.chinacloudapi.cn",
    ] {
        svc_cfg(&format!("[services.s3.cloud]\nauthority_host = {ok:?}\n")).unwrap();
    }
    for bad in ["evil.example", "login.microsoftonline.com.evil.test", ""] {
        let e = refused(&format!("[services.s3.cloud]\nauthority_host = {bad:?}\n"));
        assert!(e.contains("authority_host"), "{bad}: {e}");
    }
}

#[test]
fn cloud_unknown_key_refused() {
    assert!(toml::from_str::<SystemConfig>(
        "version = 2\n[services.a]\nconnector = \"x\"\n[services.a.cloud]\ntoken_uri = \"x\"\n"
    )
    .is_err());
    let (_d, cfg) = etc(
        "version = 2\n[services.a]\nconnector = \"x\"\n[services.a.cloud]\nroles = 1\n",
        &[],
    );
    assert!(load_system(&cfg).is_err());
}

#[test]
fn environment_cannot_set_mode_or_cloud() {
    for (key, val) in [("mode", "\"sts\""), ("cloud", "{ role_arn = \"x\" }")] {
        let (_d, cfg) = etc(
            &format!(
                "version = 2\n[services.a]\nconnector = \"x\"\n[environments.e]\nservices.a.{key} = {val}\n"
            ),
            &[],
        );
        let e = load_system(&cfg).unwrap_err().to_string();
        assert!(e.contains(key), "{key}: {e}");
    }
}

#[test]
fn policy_hash_changes_with_mode() {
    use saiife_policy::{active_packs, effective_policy, policy_hash};
    let h = |extra: &str| {
        let p = svc_cfg(extra).unwrap();
        let (packs, _) = active_packs(&p.config, &[], None);
        policy_hash(&effective_policy(&p.config, &packs, None, None))
    };
    let body =
        format!("[services.s3.cloud]\nrole_arn = \"{ROLE}\"\nrun_allow = [\"/usr/bin/aws\"]\n");
    let sts = format!("mode = \"sts\"\n{body}");
    assert_ne!(h(""), h(&sts));
    assert_ne!(h(&sts), h(&body));
    assert_ne!(h(""), h(&body));
}

const OLD_CFG: &str =
    "version = 2\n[services.s3]\nconnector = \"aws-s3\"\nallow = [\"objects:read\"]\n";

#[test]
fn cloud_keys_keep_old_hashes() {
    use saiife_policy::{active_packs, effective_policy, policy_hash};
    let (_d, cfg) = etc(OLD_CFG, &[]);
    let p = load_system(&cfg).unwrap();
    let (packs, _) = active_packs(&p.config, &[], None);
    let h = policy_hash(&effective_policy(&p.config, &packs, None, None));
    // Computed on the tree before the cloud keys existed.
    assert_eq!(
        h,
        "sha256:79401deacbde1d240dbe27a75fd2545ddf4ee4b513a5af949c7265ada1be2b9b"
    );
}

#[test]
fn run_allow_without_file_name_refused() {
    for bad in ["/", "/usr/bin/.."] {
        let e = refused(&format!("[services.s3.cloud]\nrun_allow = [{bad:?}]\n"));
        assert!(e.contains("no file name"), "{bad}: {e}");
        let (_d, cfg) = etc(
            &format!("version = 2\n[secrets.k]\nrun_allow = [{bad:?}]\n"),
            &[],
        );
        let e = load_system(&cfg).unwrap_err().to_string();
        assert!(e.contains("no file name"), "{bad}: {e}");
    }
}

/// `load_system_with` reads the drop-ins from the dir it is given, never
/// from the config's own `policy.d`.
#[test]
fn load_system_with_uses_the_given_dropin_dir() {
    let (_a, cfg) = etc(
        "version = 2\nlocked = true\n",
        &[("50-bad.toml", "this is = not toml [\n")],
    );
    assert!(load_system(&cfg).is_err());
    let other = tempfile::tempdir().unwrap();
    let missing = other.path().join("policy.d");
    let l = saiife_policy::load_system_with(&cfg, &missing).unwrap();
    assert_eq!(l.files.len(), 1, "{:?}", l.files);
    fs::create_dir(&missing).unwrap();
    fs::write(missing.join("60-bad.toml"), "nope = [\n").unwrap();
    match saiife_policy::load_system_with(&cfg, &missing) {
        Err(PolicyError::Parse { path, .. }) => assert!(path.ends_with("60-bad.toml"), "{path:?}"),
        other => panic!("{other:?}"),
    }
}
