//! The `/etc/saiife/config.toml` that `system install` writes when there is
//! none and no `--config` (spec §8.1): `locked = true`, and every other key
//! as a comment holding its default.

use crate::layout::{Layout, AUDIT_DIR, RUN_DIR};

/// One section: its header and `(key, default as TOML)` pairs.
type Section = (&'static str, &'static [(&'static str, &'static str)]);

const SECTIONS: &[Section] = &[
    (
        "daemon",
        &[("user", "\"saiife\""), ("socket_dir", "\"/run/saiife\"")],
    ),
    ("admin", &[("groups", "[]")]),
    (
        "guard",
        &[
            ("packs", "[]"),
            ("ask", "[]"),
            ("budget_ms", "50"),
            ("fail", "\"closed\""),
        ],
    ),
    ("guard.mcp", &[("allow_servers", "[]")]),
    (
        "audit",
        &[
            ("dir", "\"/var/log/saiife/audit\""),
            ("retention_months", "24"),
            ("checkpoint_every", "1000"),
            ("checkpoint_interval", "\"15m\""),
            ("min_free_mb", "512"),
            ("fsync", "\"checkpoint\""),
        ],
    ),
    (
        "approval",
        &[
            ("approvers", "[]"),
            ("same_user", "\"deny\""),
            ("timeout", "\"30m\""),
            ("grant_ttl", "\"15m\""),
        ],
    ),
    (
        "gateway",
        &[
            ("tcp", "\"\""),
            ("max_response_bytes", "5242880"),
            ("upstream_timeout", "\"30s\""),
        ],
    ),
];

const HEADER: &str = "\
# saiife system config (spec §8.1). Every other key is shown below with its
# default: remove the leading \"# \" to change one. Services, scopes, notify
# targets and audit forwarding have no defaults; see the docs. Drop-ins in
# policy.d/*.toml are read after this file, in name order.
";

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// The default config. `approvers` (user names or `group:<name>`, checked by
/// the caller) are written uncommented. Under a test root the daemon user,
/// socket dir and audit dir are written uncommented too, pointing below the
/// root, so a test never points at the real `/run` or `/var`.
pub fn default_config(layout: &Layout, approvers: &[String]) -> String {
    let mut set: Vec<(&str, &str, String)> = Vec::new();
    if !approvers.is_empty() {
        let list: Vec<String> = approvers.iter().map(|a| toml_str(a)).collect();
        set.push(("approval", "approvers", format!("[{}]", list.join(", "))));
    }
    if !layout.is_system() {
        let at = |p: &str| toml_str(&layout.at(p).to_string_lossy());
        set.push(("daemon", "user", toml_str(&own_user_name())));
        set.push(("daemon", "socket_dir", at(RUN_DIR)));
        set.push(("audit", "dir", at(AUDIT_DIR)));
    }
    let mut out = String::from("version = 2\nlocked = true\n\n");
    out.push_str(HEADER);
    for (section, keys) in SECTIONS {
        let overridden = set.iter().any(|(s, _, _)| s == section);
        out.push('\n');
        if overridden {
            out.push_str(&format!("[{section}]\n"));
        } else {
            out.push_str(&format!("# [{section}]\n"));
        }
        for (key, default) in *keys {
            match set.iter().find(|(s, k, _)| s == section && k == key) {
                Some((_, _, v)) => out.push_str(&format!("{key} = {v}\n")),
                None => out.push_str(&format!("# {key} = {default}\n")),
            }
        }
    }
    out
}

/// This process's user name from `/etc/passwd` (else `$USER`).
fn own_user_name() -> String {
    let uid = rustix::process::getuid().as_raw();
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() >= 3 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[0].to_string())
            })
        })
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "nobody".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_policy::system::SystemConfig;
    use std::path::Path;

    fn load(text: &str) -> SystemConfig {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(&p, text).unwrap();
        saiife_policy::load_system(&p)
            .unwrap_or_else(|e| panic!("{e}\n{text}"))
            .config
    }

    fn defaults() -> SystemConfig {
        let mut c: SystemConfig = toml::from_str("version = 2\nlocked = true\n").unwrap();
        c.locked = true;
        c
    }

    /// Every commented key and header, uncommented.
    fn uncomment(text: &str) -> String {
        text.lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(rest)
                    if rest.starts_with('[')
                        || rest.split_once(" = ").is_some_and(|(k, _)| {
                            k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        }) =>
                {
                    rest
                }
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn system_default_is_locked_and_all_defaults() {
        let t = default_config(&Layout::system(), &[]);
        assert!(t.starts_with("version = 2\nlocked = true\n"), "{t}");
        assert_eq!(load(&t), defaults());
        // Every key shown is a real key holding its default.
        let all = uncomment(&t);
        assert!(all.contains("\n[guard.mcp]\nallow_servers = []\n"), "{all}");
        assert_eq!(load(&all), defaults());
        // Every key of every section is listed.
        let n_keys: usize = SECTIONS.iter().map(|(_, k)| k.len()).sum();
        assert_eq!(
            t.lines()
                .filter(|l| l.contains(" = ") && l.starts_with("# "))
                .count(),
            n_keys
        );
    }

    #[test]
    fn approvers_are_written_uncommented() {
        let t = default_config(
            &Layout::system(),
            &["alice".into(), "group:saiife-approvers".into()],
        );
        let c = load(&t);
        assert_eq!(c.approval.approvers, ["alice", "group:saiife-approvers"]);
        assert!(
            t.contains(
                "\n[approval]\napprovers = [\"alice\", \"group:saiife-approvers\"]\n# same_user"
            ),
            "{t}"
        );
        assert_eq!(load(&uncomment(&t)).approval.approvers.len(), 2);
    }

    #[test]
    fn test_root_points_below_the_root() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        let t = default_config(&l, &[]);
        let c = load(&t);
        assert_eq!(c.daemon.socket_dir, l.root().join("run/saiife"));
        assert_eq!(c.audit.dir, l.root().join("var/log/saiife/audit"));
        assert_eq!(c.daemon.user, own_user_name());
        assert_ne!(c.daemon.user, "saiife");
        assert!(c.locked);
        assert!(!t.contains("\n# [daemon]"), "{t}");
        assert!(Path::new(&c.daemon.socket_dir).starts_with(l.root()));
    }
}
