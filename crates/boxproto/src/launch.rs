//! The agent process's environment in a box (COORD-7): an explicit,
//! saiife-built allowlist, the same for every agent kind except each one's
//! own model variables, and the one forced git-config table.
//!
//! The guest init starts the agent with `env_clear()` and exactly
//! [`launch_env`]. `runuser -u agent` (no `-l`, no `-p`) then sets `HOME`,
//! `SHELL`, `USER` and `LOGNAME` from the agent's passwd entry; those are in
//! [`fixed_env`] with the same values, so the agent sees the allowlist and
//! nothing else. (`runuser` also sets `PATH` only with `ALWAYS_SET_PATH=yes`
//! in `/etc/login.defs`, not set on Ubuntu, and merges what its PAM stack
//! exports; Debian's `/etc/pam.d/runuser` has no `pam_env`.)
//!
//! Everything outside the allowlist (`LD_*`, `BASH_ENV`, `ENV`,
//! `NODE_OPTIONS`, `GIT_*` program variables, …) is absent by construction:
//! a host setup that names any variable but a model one
//! ([`MODEL_ENV`]) is refused by `Setup::check`, which the guest runs too.
//!
//! Threat-model boundary (2026-11-17): in-box hardening is best-effort
//! defence in depth; the agent can already run arbitrary code in its box.
//! What is guaranteed is the guard hook's integrity against repo config, no
//! real credentials in the box, egress only via the gateway, and every
//! change reviewed and landed by touch on the host.

use crate::ports::{AGENT_HOME, AGENT_LANG, AGENT_NO_PROXY, AGENT_PATH, AGENT_PROXY, AGENT_USER};

/// The agent's login shell (`useradd -s /bin/bash` in the bake); `runuser`
/// sets `SHELL` to it.
pub const AGENT_SHELL: &str = "/bin/bash";
/// The agent's `TERM` (its pty).
pub const AGENT_TERM: &str = "xterm-256color";

/// The git config file every agent's git reads as its global config,
/// baked root:root 0644 in a 0755 dir. No system file is read
/// (`GIT_CONFIG_NOSYSTEM=1`), and the agent's `~/.gitconfig` is not read.
pub const GIT_CONFIG_GLOBAL_PATH: &str = "/etc/saiife/gitconfig";

/// git's ssh program in a box (FU2 fix 5): a baked root-owned wrapper that
/// runs `/usr/bin/ssh` with only saiife's ssh config.
pub const GIT_SSH_WRAPPER: &str = "/usr/local/libexec/saiife-ssh";

/// `diff.external` (and `GIT_EXTERNAL_DIFF` where pinned). git has no value
/// that turns an external diff off (an empty one makes `git diff` fail with
/// "cannot run :"), so the forced value is a plain unified diff of the two
/// files, labelled `a/<path>` and `b/<path>` like git's own, from diffutils
/// (Essential on Ubuntu). git runs it through `sh -c` with its seven
/// arguments (path, old file, old hex, old mode, new file, new hex, new
/// mode); exit 1 (differ) and 2 (binary) count as success, as git expects 0
/// without `diff.trustExitCode`.
pub const GIT_DIFF_COMMAND: &str =
    "f() { /usr/bin/diff -u --label \"a/$1\" --label \"b/$1\" -- \"$2\" \"$5\"; [ $? -le 2 ]; }; f";

/// The git config keys saiife forces in a box: the baked
/// [`GIT_CONFIG_GLOBAL_PATH`] file ([`gitconfig_text`]) and the
/// `GIT_CONFIG_COUNT` pairs of [`git_env`] are both built from this table.
/// The env pairs "override values in configuration files"
/// (git-config(1), ENVIRONMENT), so a repo's `.git/config` cannot move them;
/// the file covers a process that lost the env pairs.
/// - `core.sshCommand`: [`GIT_SSH_WRAPPER`]; empty `core.askPass` and
///   `credential.helper` (no askpass; an empty helper clears the list);
///   `core.fsmonitor=false`; `core.pager=cat` (git's "no pager").
/// - `protocol.*`: unknown protocols only when the user typed them, https
///   always, `ext::` never, local files only when typed.
/// - signing programs `/bin/false` (a signed commit fails, nothing runs).
/// - `diff.external`: [`GIT_DIFF_COMMAND`].
/// - editors `true` (an edit-less commit aborts; a rebase todo is kept).
/// - `core.hooksPath=/dev/null`: "disable all hooks entirely"
///   (git-config(1)); repo hooks never run on the agent's git commands.
pub const GIT_FORCED_CONFIG: [(&str, &str); 15] = [
    ("core.sshCommand", GIT_SSH_WRAPPER),
    ("core.askPass", ""),
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("credential.helper", ""),
    ("protocol.allow", "user"),
    ("protocol.https.allow", "always"),
    ("protocol.ext.allow", "never"),
    ("protocol.file.allow", "user"),
    ("gpg.program", "/bin/false"),
    ("gpg.ssh.program", "/bin/false"),
    ("diff.external", GIT_DIFF_COMMAND),
    ("sequence.editor", "true"),
    ("core.editor", "true"),
    ("core.hooksPath", "/dev/null"),
];

/// The value of `key` in [`GIT_FORCED_CONFIG`].
pub fn forced(key: &str) -> &'static str {
    GIT_FORCED_CONFIG
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .unwrap_or_else(|| panic!("{key} is not forced"))
}

/// The model variables the host may send in a setup, per agent (plan 40 C2,
/// plan 42 D5): the only ones `Setup::check` accepts. A setup does not name
/// its agent kind, so the check accepts the union; the host sends one
/// agent's.
pub const MODEL_ENV: [(&str, &[&str]); 3] = [
    (
        "claude",
        &[
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "DISABLE_TELEMETRY",
            "DISABLE_ERROR_REPORTING",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "DISABLE_AUTOUPDATER",
        ],
    ),
    ("codex", &["OPENAI_API_KEY", "CODEX_HOME"]),
    (
        "gemini",
        &[
            "GEMINI_API_KEY",
            "GOOGLE_GEMINI_BASE_URL",
            "GEMINI_TELEMETRY_ENABLED",
            "GEMINI_CLI_HOME",
        ],
    ),
];

/// Whether `name` is some agent's model variable ([`MODEL_ENV`]).
pub fn is_model_var(name: &str) -> bool {
    MODEL_ENV.iter().any(|(_, vars)| vars.contains(&name))
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The fixed part of the allowlist: the agent's identity (the values
/// `runuser` sets too), `PATH`, `TERM`, `LANG` and the egress proxy (upper
/// and lower case: curl reads only the lower-case `http_proxy`).
pub fn fixed_env() -> Vec<(String, String)> {
    pairs(&[
        ("HOME", AGENT_HOME),
        ("USER", AGENT_USER),
        ("LOGNAME", AGENT_USER),
        ("SHELL", AGENT_SHELL),
        ("PATH", AGENT_PATH),
        ("TERM", AGENT_TERM),
        ("LANG", AGENT_LANG),
        ("HTTPS_PROXY", AGENT_PROXY),
        ("HTTP_PROXY", AGENT_PROXY),
        ("https_proxy", AGENT_PROXY),
        ("http_proxy", AGENT_PROXY),
        ("NO_PROXY", AGENT_NO_PROXY),
        ("no_proxy", AGENT_NO_PROXY),
    ])
}

/// git's part of the allowlist: [`GIT_CONFIG_GLOBAL_PATH`] as the global
/// config, no system config, and [`GIT_FORCED_CONFIG`] as
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`.
pub fn git_env() -> Vec<(String, String)> {
    let mut v = pairs(&[
        ("GIT_CONFIG_GLOBAL", GIT_CONFIG_GLOBAL_PATH),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ]);
    v.push((
        "GIT_CONFIG_COUNT".into(),
        GIT_FORCED_CONFIG.len().to_string(),
    ));
    for (i, (k, val)) in GIT_FORCED_CONFIG.iter().enumerate() {
        v.push((format!("GIT_CONFIG_KEY_{i}"), k.to_string()));
        v.push((format!("GIT_CONFIG_VALUE_{i}"), val.to_string()));
    }
    v
}

/// The agent's whole environment: [`fixed_env`], [`git_env`], then the
/// setup's model variables. Anything else in `setup_env` is dropped (the
/// setup check has already refused it; this is the second line).
pub fn launch_env(setup_env: &[(String, String)]) -> Vec<(String, String)> {
    let mut v = fixed_env();
    v.extend(git_env());
    v.extend(setup_env.iter().filter(|(k, _)| is_model_var(k)).cloned());
    v
}

/// One git config value, quoted: `"`, `\` escaped, so `;`, `#` and spaces
/// in [`GIT_DIFF_COMMAND`] stay part of the value.
fn quote(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The text of [`GIT_CONFIG_GLOBAL_PATH`]: [`GIT_FORCED_CONFIG`] as git
/// config sections (`protocol.https.allow` is `[protocol "https"] allow`).
pub fn gitconfig_text() -> String {
    let mut out = String::from("# saiife: the git config of every agent in a box (COORD-7)\n");
    let mut section = String::new();
    for (k, v) in GIT_FORCED_CONFIG {
        let (head, name) = k.rsplit_once('.').expect("section.name");
        let head = match head.split_once('.') {
            Some((sec, sub)) => format!("[{sec} \"{sub}\"]"),
            None => format!("[{head}]"),
        };
        if head != section {
            out.push_str(&head);
            out.push('\n');
            section = head;
        }
        out.push_str(&format!("\t{name} = {}\n", quote(v)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(v: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs(v)
    }

    /// A tiny git config reader for the text above (sections, subsections,
    /// quoted values with `\"` and `\\`): what git would parse it to.
    fn parse(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut sec = String::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some(h) = l.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
                sec = match h.split_once(" \"") {
                    Some((s, sub)) => format!("{s}.{}", sub.trim_end_matches('"')),
                    None => h.to_string(),
                };
                continue;
            }
            let (name, val) = l.split_once(" = ").expect("name = value");
            let inner = val
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap();
            let mut v = String::new();
            let mut it = inner.chars();
            while let Some(c) = it.next() {
                if c == '\\' {
                    v.push(it.next().unwrap());
                } else {
                    assert_ne!(c, '"', "unescaped quote in {line}");
                    v.push(c);
                }
            }
            out.push((format!("{sec}.{name}"), v));
        }
        out
    }

    /// One table, two outputs: the env pairs and the baked file carry
    /// exactly [`GIT_FORCED_CONFIG`], in order.
    #[test]
    fn the_forced_git_table_feeds_the_env_and_the_file() {
        let table: Vec<(String, String)> = kv(&GIT_FORCED_CONFIG);
        assert_eq!(parse(&gitconfig_text()), table);
        let env = git_env();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("GIT_CONFIG_COUNT"), Some(table.len().to_string()));
        for (i, (k, v)) in table.iter().enumerate() {
            assert_eq!(get(&format!("GIT_CONFIG_KEY_{i}")).as_ref(), Some(k));
            assert_eq!(get(&format!("GIT_CONFIG_VALUE_{i}")).as_ref(), Some(v));
        }
        assert_eq!(env.len(), 3 + 2 * table.len());
        assert_eq!(
            get("GIT_CONFIG_GLOBAL").as_deref(),
            Some("/etc/saiife/gitconfig")
        );
        assert_eq!(get("GIT_CONFIG_NOSYSTEM").as_deref(), Some("1"));
    }

    /// The table, verbatim (the brief's values; `diff.external` is the
    /// labelled plain diff because git runs an empty one as `""`).
    #[test]
    fn the_forced_git_table_is_pinned() {
        assert_eq!(
            kv(&GIT_FORCED_CONFIG),
            kv(&[
                ("core.sshCommand", "/usr/local/libexec/saiife-ssh"),
                ("core.askPass", ""),
                ("core.fsmonitor", "false"),
                ("core.pager", "cat"),
                ("credential.helper", ""),
                ("protocol.allow", "user"),
                ("protocol.https.allow", "always"),
                ("protocol.ext.allow", "never"),
                ("protocol.file.allow", "user"),
                ("gpg.program", "/bin/false"),
                ("gpg.ssh.program", "/bin/false"),
                (
                    "diff.external",
                    "f() { /usr/bin/diff -u --label \"a/$1\" --label \"b/$1\" -- \"$2\" \"$5\"; [ $? -le 2 ]; }; f",
                ),
                ("sequence.editor", "true"),
                ("core.editor", "true"),
                ("core.hooksPath", "/dev/null"),
            ])
        );
        assert_eq!(forced("core.hooksPath"), "/dev/null");
        assert!(gitconfig_text().contains("[protocol \"https\"]\n\tallow = \"always\"\n"));
        assert!(gitconfig_text().contains("[gpg \"ssh\"]\n\tprogram = \"/bin/false\"\n"));
        assert!(gitconfig_text().contains("[credential]\n\thelper = \"\"\n"));
    }

    /// The launch env is exactly the allowlist: the fixed values, git's,
    /// then the setup's model variables; anything else is dropped.
    #[test]
    fn launch_env_is_the_allowlist() {
        let setup = kv(&[
            ("OPENAI_API_KEY", "PH"),
            ("LD_PRELOAD", "/work/x.so"),
            ("PATH", "/work/bin"),
            ("CODEX_HOME", "/home/agent/.codex"),
        ]);
        let mut want = kv(&[
            ("HOME", "/home/agent"),
            ("USER", "agent"),
            ("LOGNAME", "agent"),
            ("SHELL", "/bin/bash"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("TERM", "xterm-256color"),
            ("LANG", "C.UTF-8"),
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
            ("HTTP_PROXY", "http://127.0.0.1:3128"),
            ("https_proxy", "http://127.0.0.1:3128"),
            ("http_proxy", "http://127.0.0.1:3128"),
            ("NO_PROXY", "localhost,127.0.0.1"),
            ("no_proxy", "localhost,127.0.0.1"),
        ]);
        want.extend(git_env());
        want.extend(kv(&[
            ("OPENAI_API_KEY", "PH"),
            ("CODEX_HOME", "/home/agent/.codex"),
        ]));
        assert_eq!(launch_env(&setup), want);
    }

    #[test]
    fn model_vars_are_the_agents_own() {
        for v in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_CLI_HOME"] {
            assert!(is_model_var(v), "{v}");
        }
        for v in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "BASH_ENV",
            "ENV",
            "NODE_OPTIONS",
            "PATH",
            "HOME",
            "SHELL",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_GLOBAL",
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH_COMMAND",
            "PROMPT_COMMAND",
            "PYTHONPATH",
        ] {
            assert!(!is_model_var(v), "{v}");
        }
        // no model variable is also a fixed or git one
        for (k, _) in fixed_env().iter().chain(git_env().iter()) {
            assert!(!is_model_var(k), "{k}");
        }
    }
}
