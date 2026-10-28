//! `[environments.<name>]` (spec §6.11, plan 14 decision 10): the overlay,
//! its load-time checks, the scope binding and the effective-policy hash.

use saiife_policy::environment::{apply, env_for};
use saiife_policy::{
    active_packs, effective_policy, load_system, merge_project, parse_project, policy_hash,
    FixedDirectory, Mode, PackInfo, PolicyError, SystemConfig,
};
use std::fs;
use std::path::PathBuf;

/// The §6.11 blocks, on a base config with a shopify service.
const SPEC: &str = r#"version = 2
locked = true

[guard]
packs = ["db.postgres"]

[services.shopify]
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme", api_version = "2024-10" }
allow = ["orders:read", "products:read"]
ask = ["orders:write"]

[services.shopify.limits]
requests_per_minute = 60
writes_per_hour = 10

[[scope]]
name = "shop-agent"
users = ["agent-shop"]
services = ["shopify"]
env = "prod"

[[scope]]
name = "shop-staging"
users = ["agent-stage"]
services = ["shopify"]
env = "staging"

[environments.staging]
services.shopify.secret = "shopify-staging"
services.shopify.params = { shop = "acme-staging" }

[environments.prod]
guard.packs = ["iac.terraform", "db.postgres"]      # added to the base list
services.shopify.ask = ["products:write"]
"#;

const PASSWD: &str = "agent-shop:x:1000:1000::/home/a:/bin/sh\n\
    agent-stage:x:1001:1001::/home/b:/bin/sh\n\
    nobody2:x:1002:1002::/home/c:/bin/sh\n";

fn etc(config: &str) -> (tempfile::TempDir, PathBuf) {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&base).unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    let cfg = dir.path().join("config.toml");
    fs::write(&cfg, config).unwrap();
    (dir, cfg)
}

fn load(config: &str) -> Result<SystemConfig, PolicyError> {
    let (_d, path) = etc(config);
    load_system(&path).map(|l| l.config)
}

fn load_err(config: &str) -> String {
    match load(config) {
        Ok(_) => panic!("expected the policy to be refused"),
        Err(e) => e.to_string(),
    }
}

fn catalog() -> Vec<PackInfo> {
    let p = |id: &str, default_on| PackInfo {
        id: id.into(),
        version: 1,
        default_on,
        rules: Vec::new(),
    };
    vec![
        p("core.git", true),
        p("core.filesystem", true),
        p("db.postgres", false),
        p("iac.terraform", false),
    ]
}

fn hash(cfg: &SystemConfig, env: Option<&str>) -> String {
    let applied = match env {
        Some(e) => apply(cfg, e).unwrap(),
        None => cfg.clone(),
    };
    let (packs, _) = active_packs(&applied, &catalog(), None);
    policy_hash(&effective_policy(&applied, &packs, None, env))
}

#[test]
fn spec_example_applies() {
    let cfg = load(SPEC).unwrap();
    assert_eq!(cfg.environments.len(), 2);

    let staging = apply(&cfg, "staging").unwrap();
    let s = &staging.services["shopify"];
    assert_eq!(s.secret.as_deref(), Some("shopify-staging"));
    assert_eq!(s.params["shop"], "acme-staging");
    // params merge per field.
    assert_eq!(s.params["api_version"], "2024-10");
    // Keys the environment does not set keep the base value.
    assert_eq!(s.ask, vec!["orders:write"]);
    assert_eq!(s.allow, vec!["orders:read", "products:read"]);
    assert_eq!(s.connector, "shopify");

    let prod = apply(&cfg, "prod").unwrap();
    let p = &prod.services["shopify"];
    // A list that is present replaces the base list.
    assert_eq!(p.ask, vec!["products:write"]);
    assert_eq!(p.secret.as_deref(), Some("shopify-prod"));
    assert_eq!(p.params["shop"], "acme");
    // Packs are base ∪ env.
    assert!(prod.guard.packs.contains(&"iac.terraform".to_string()));
    assert!(prod.guard.packs.contains(&"db.postgres".to_string()));
    assert_eq!(
        prod.guard
            .packs
            .iter()
            .filter(|p| p.as_str() == "db.postgres")
            .count(),
        1,
        "{:?}",
        prod.guard.packs
    );
    let (packs, _) = active_packs(&prod, &catalog(), None);
    assert!(packs.iter().any(|p| p.id == "iac.terraform"));

    // The base is untouched.
    assert_eq!(cfg.services["shopify"].ask, vec!["orders:write"]);
    assert!(apply(&cfg, "nope").is_err());
}

#[test]
fn limits_and_fixed_merge_per_field() {
    let text = SPEC.replace(
        "[environments.prod]\n",
        "[environments.prod]\n\
         services.shopify.limits = { writes_per_hour = 2 }\n\
         services.shopify.fixed = { a = \"1\" }\n\
         services.shopify.redact = { fields = [\"email\"] }\n\
         services.shopify.rule = [{ capability = \"orders:write\", action = \"deny\" }]\n",
    );
    let cfg = load(&text).unwrap();
    let prod = apply(&cfg, "prod").unwrap();
    let p = &prod.services["shopify"];
    assert_eq!(p.limits.writes_per_hour, Some(2));
    assert_eq!(p.limits.requests_per_minute, Some(60));
    assert_eq!(p.fixed["a"], "1");
    assert_eq!(p.redact.fields, vec!["email"]);
    assert_eq!(p.rule.len(), 1);
}

#[test]
fn env_cannot_drop_default_pack() {
    // An empty pack list adds nothing and removes nothing.
    let text = SPEC.replace(
        "guard.packs = [\"iac.terraform\", \"db.postgres\"]",
        "guard.packs = []",
    );
    let cfg = load(&text).unwrap();
    let prod = apply(&cfg, "prod").unwrap();
    assert_eq!(prod.guard.packs, vec!["db.postgres"]);
    let (packs, _) = active_packs(&prod, &catalog(), None);
    for id in ["core.git", "core.filesystem", "db.postgres"] {
        assert!(packs.iter().any(|p| p.id == id), "{id} missing: {packs:?}");
    }
    // There is no key that removes a pack.
    for key in ["remove", "disable", "exclude", "ask", "budget_ms", "fail"] {
        let text = SPEC.replace(
            "guard.packs = [\"iac.terraform\", \"db.postgres\"]",
            &format!("guard.{key} = [\"core.git\"]"),
        );
        let e = load_err(&text);
        assert!(e.contains(key), "{key}: {e}");
    }
}

#[test]
fn env_cannot_override_connector() {
    for (key, value) in [
        ("connector", "\"http\""),
        ("base_url", "\"https://evil.test\""),
        ("operation", "[]"),
        ("auth", "{ kind = \"bearer\" }"),
    ] {
        let text = SPEC.replace(
            "services.shopify.ask = [\"products:write\"]",
            &format!("services.shopify.{key} = {value}"),
        );
        let e = load_err(&text);
        assert!(e.contains("unknown field") && e.contains(key), "{key}: {e}");
    }
}

#[test]
fn env_unknown_service_refused() {
    let text = SPEC.replace(
        "services.shopify.ask = [\"products:write\"]",
        "services.stripe.secret = \"stripe-prod\"",
    );
    let e = load_err(&text);
    assert!(e.contains("prod") && e.contains("stripe"), "{e}");
}

#[test]
fn env_override_patterns_validated() {
    let text = SPEC.replace(
        "services.shopify.ask = [\"products:write\"]",
        "services.shopify.ask = [\"\"]",
    );
    let e = load_err(&text);
    assert!(
        e.contains("prod") && e.contains("capability pattern"),
        "{e}"
    );
}

#[test]
fn scope_env_undefined_refuses_policy() {
    let text = SPEC.replace("env = \"staging\"", "env = \"qa\"");
    let e = load_err(&text);
    assert!(e.contains("qa") && e.contains("shop-staging"), "{e}");
    // No environments at all: the same.
    let e = load_err("version = 2\n[[scope]]\nname = \"s\"\nusers = [\"u\"]\nenv = \"prod\"\n");
    assert!(e.contains("prod"), "{e}");
}

#[test]
fn environments_only_in_config_toml() {
    let (d, path) = etc(SPEC);
    fs::create_dir(d.path().join("policy.d")).unwrap();
    fs::write(
        d.path().join("policy.d/x.toml"),
        "[environments.dev]\nguard.packs = [\"db.postgres\"]\n",
    )
    .unwrap();
    let e = load_system(&path).unwrap_err().to_string();
    assert!(
        e.contains("environments may only be set in config.toml"),
        "{e}"
    );
}

#[test]
fn environment_names_are_checked() {
    let text = SPEC.replace("[environments.staging]", "[environments.\"Bad Name\"]");
    let text = text.replace("env = \"staging\"", "env = \"Bad Name\"");
    let e = load_err(&text);
    assert!(e.contains("environment name"), "{e}");
}

#[test]
fn hash_differs_per_env() {
    let cfg = load(SPEC).unwrap();
    let base = hash(&cfg, None);
    let staging = hash(&cfg, Some("staging"));
    let prod = hash(&cfg, Some("prod"));
    assert_ne!(base, staging);
    assert_ne!(base, prod);
    assert_ne!(staging, prod);
    // An environment that changes nothing still has its own hash.
    let text = format!("{SPEC}[environments.empty]\n");
    let cfg = load(&text).unwrap();
    assert_ne!(hash(&cfg, None), hash(&cfg, Some("empty")));
    // And the hash names it.
    let applied = apply(&cfg, "staging").unwrap();
    let (packs, _) = active_packs(&applied, &catalog(), None);
    let v = effective_policy(&applied, &packs, None, Some("staging"));
    assert_eq!(v["env"], "staging");
    assert_eq!(
        effective_policy(&cfg, &packs, None, None)["env"],
        serde_json::Value::Null
    );
}

#[test]
fn env_for_is_the_scope_env() {
    let cfg = load(SPEC).unwrap();
    let d = FixedDirectory::from_text(PASSWD, "");
    assert_eq!(env_for(&cfg, &d, "agent-shop").unwrap(), Some("prod"));
    assert_eq!(env_for(&cfg, &d, "agent-stage").unwrap(), Some("staging"));
    assert_eq!(env_for(&cfg, &d, "nobody2").unwrap(), None);
}

#[test]
fn locked_project_env_ignored() {
    let cfg = load(SPEC).unwrap();
    let d = FixedDirectory::from_text(PASSWD, "");
    let p = parse_project(b"version = 2\nenv = \"staging\"\n").unwrap();
    let m = merge_project(&cfg.guard.packs, &p, Mode::Locked);
    assert!(
        m.notes.iter().any(|n| n == "env ignored in locked mode"),
        "{:?}",
        m.notes
    );
    // The scope's environment is the one in force; the project's is not
    // an input to env_for at all.
    assert_eq!(env_for(&cfg, &d, "agent-shop").unwrap(), Some("prod"));
}

#[test]
fn reserved_service_names_refused() {
    for name in ["collection", "result", "token", "saiife"] {
        let e = load_err(&format!(
            "version = 2\n[services.{name}]\nconnector = \"http\"\n"
        ));
        assert!(e.contains(name) && e.contains("reserved"), "{name}: {e}");
    }
}
