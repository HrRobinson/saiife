use saiife_policy::{load_system, PolicyError};
use std::fs;
use std::path::PathBuf;

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

const LOCKED: &str = "version = 2\nlocked = true\n";
const LINEAR: &str = "[mcp.linear]\ncommand = \"/usr/bin/linear-mcp\"\nargs = [\"--stdio\"]\nenv = { LINEAR_TOKEN = \"linear-api\" }\nallow = [\"list_*\"]\nask = [\"create_*\"]\nread_tools = [\"list_*\"]\n";

// The gateway loads on Linux only (plan 13, decision 7).
#[cfg(target_os = "linux")]
#[test]
fn mcp_dropin_parses() {
    let (_d, cfg) = etc(LOCKED, &[("mcp-linear.toml", LINEAR)]);
    let p = load_system(&cfg).unwrap();
    let s = &p.config.mcp["linear"];
    assert_eq!(s.command, PathBuf::from("/usr/bin/linear-mcp"));
    assert_eq!(s.env["LINEAR_TOKEN"], "linear-api");
    assert_eq!(s.timeout, std::time::Duration::from_secs(30));
}

/// Plan 13, decision 7: no gateway outside Linux in v2.1, in either mode.
#[cfg(not(target_os = "linux"))]
#[test]
fn mcp_dropin_is_load_error_off_linux() {
    for config in [LOCKED, "version = 2\n"] {
        let (_d, cfg) = etc(config, &[("mcp-linear.toml", LINEAR)]);
        let e = load_system(&cfg).unwrap_err().to_string();
        assert!(e.contains(saiife_policy::mcp::MCP_NEEDS_LINUX), "{e}");
    }
}

#[test]
fn mcp_duplicate_across_files_is_error() {
    let (_d, cfg) = etc(LOCKED, &[("10.toml", LINEAR), ("20.toml", LINEAR)]);
    match load_system(&cfg).unwrap_err() {
        PolicyError::DuplicateService { name, .. } => assert_eq!(name, "mcp:linear"),
        other => panic!("{other:?}"),
    }
}

// The gateway loads on Linux only (plan 13, decision 7).
#[cfg(target_os = "linux")]
#[test]
fn gateway_refused_outside_locked() {
    let (_d, cfg) = etc("version = 2\n", &[("mcp-linear.toml", LINEAR)]);
    let e = load_system(&cfg).unwrap_err().to_string();
    assert!(e.contains("the MCP gateway needs locked mode"), "{e}");
}

// The gateway loads on Linux only (plan 13, decision 7).
#[cfg(target_os = "linux")]
#[test]
fn allow_servers_overlap_refused_with_message() {
    let (_d, cfg) = etc(
        LOCKED,
        &[
            ("mcp-linear.toml", LINEAR),
            ("x.toml", "[guard.mcp]\nallow_servers = [\"linear\"]\n"),
        ],
    );
    let e = load_system(&cfg).unwrap_err().to_string();
    assert!(
        e.contains("MCP server linear is both unbrokered ([guard.mcp] allow_servers) and brokered ([mcp.linear]); remove it from allow_servers"),
        "{e}"
    );
}

/// Controller ruling (plan 17, T9 follow-up): Codex and Gemini CLI do not
/// pin the `saiife` server's command, so their hook allows it only when it
/// is listed. Exactly `saiife` may be listed; a case variant may not.
#[test]
fn saiife_in_allow_servers_accepted_exactly() {
    let (_d, cfg) = etc(
        LOCKED,
        &[("x.toml", "[guard.mcp]\nallow_servers = [\"saiife\"]\n")],
    );
    let p = load_system(&cfg).unwrap();
    assert_eq!(p.config.guard.mcp.allow_servers, vec!["saiife".to_string()]);
    let (_d, cfg) = etc(
        LOCKED,
        &[("x.toml", "[guard.mcp]\nallow_servers = [\"Saiife\"]\n")],
    );
    let e = load_system(&cfg).unwrap_err().to_string();
    assert!(
        e.contains("[guard.mcp] allow_servers may not contain \"Saiife\"; write \"saiife\""),
        "{e}"
    );
}

#[test]
fn bad_mcp_dropin_values_refused() {
    for bad in [
        "[mcp.linear]\ncommand = \"linear-mcp\"\n",
        "[mcp.saiife]\ncommand = \"/a\"\n",
        "[mcp.a_b]\ncommand = \"/a\"\n",
        "[mcp.linear]\ncommand = \"/a\"\nbogus = 1\n",
    ] {
        let (_d, cfg) = etc(LOCKED, &[("x.toml", bad)]);
        assert!(load_system(&cfg).is_err(), "{bad}");
    }
}

#[test]
fn allow_servers_overlap_ignores_case() {
    let (_d, cfg) = etc(
        LOCKED,
        &[
            ("mcp-linear.toml", LINEAR),
            ("x.toml", "[guard.mcp]\nallow_servers = [\"Linear\"]\n"),
        ],
    );
    assert!(load_system(&cfg).is_err());
    let (_d, cfg) = etc(
        LOCKED,
        &[("x.toml", "[guard.mcp]\nallow_servers = [\"SAIIFE\"]\n")],
    );
    assert!(load_system(&cfg).is_err());
}

/// `[mcp.*]` is skipped when empty, so a config without it serializes (and
/// hashes) as it did before plan 17.
#[test]
fn no_mcp_hash_is_unchanged() {
    let (_d, cfg) = etc(LOCKED, &[]);
    let p = load_system(&cfg).unwrap();
    let v = saiife_policy::effective_policy(&p.config, &[], None, None);
    // Same value on main (1c975b5) for this config. macOS has its own
    // daemon defaults in the effective policy: the value a macOS runner
    // computed.
    let want = if cfg!(target_os = "macos") {
        "sha256:0b3a35a173f8cdbc4ccf57ad4975654be086498b2ef2ccceeb00176a12bcdabf"
    } else {
        "sha256:2865f5d87de5b97228c121d4ee0cd5b8c78b75ba2b1f06486c39823035848892"
    };
    assert_eq!(saiife_policy::policy_hash(&v), want);
}

/// Plan 17 is silent on environments, so `[mcp.*]` is not overridable there:
/// `EnvironmentCfg` has no such key and rejects it.
#[test]
fn mcp_is_not_overridable_per_environment() {
    let (_d, cfg) = etc(
        "version = 2\nlocked = true\n[environments.staging.mcp.linear]\ncommand = \"/a\"\n",
        &[],
    );
    assert!(matches!(load_system(&cfg), Err(PolicyError::Parse { .. })));
}
