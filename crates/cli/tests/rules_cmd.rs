//! `saiife rules` end to end (plan 33).

mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{code, stdout, Env};

#[test]
fn rules_help_lists_the_actions() {
    let env = Env::new(&[]);
    let out = env.saiife(&["rules", "--help"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    for word in ["import", "sync", "list"] {
        assert!(text.contains(word), "{word} missing: {text}");
    }
}

// ---- import, personal target (no /etc/saiife: an absent system config) ----

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `saiife rules <args>` in the project root, `answers` on stdin.
fn rules(env: &Env, args: &[&str], answers: &str) -> Output {
    let absent = common::absent_system_config(env.home.path());
    let mut child = env
        .command_in(env.root(), &["rules"])
        .args(args)
        .env("SAIIFE_TEST_SYSTEM_CONFIG", &absent)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// The personal broker's user pack dir under the test HOME.
fn personal_packs(env: &Env) -> PathBuf {
    if cfg!(windows) {
        env.home
            .path()
            .join("AppData/Local/saiife/personal/policy.d/packs")
    } else {
        env.home.path().join(".config/saiife/broker/policy.d/packs")
    }
}

fn pack_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy();
            n.ends_with(".toml") && !n.starts_with('.')
        })
        .collect();
    v.sort();
    v
}

/// A developer-mode hook call for a Claude Bash command: (exit, stderr).
#[cfg(unix)]
fn hook(env: &Env, cmd: &str) -> (i32, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": env.root(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    let absent = common::absent_system_config(env.home.path());
    let mut child = env
        .command_in(
            env.root(),
            &[
                "check",
                "--hook-exit",
                "--agent",
                "claude",
                "--system-config",
            ],
        )
        .arg(absent)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), stderr(&out))
}

const DEPLOY: &str = "Never run `deploy-prod`.\n";

#[test]
fn import_writes_a_pack_the_hook_enforces() {
    let env = Env::new(&["claude"]);
    env.write("CLAUDE.md", DEPLOY);
    let o = rules(&env, &["import", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let files = pack_files(&personal_packs(&env));
    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("user.claude-md-"), "{name}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let out = stdout(&o);
    assert!(
        out.contains("2 rules (0 ask), 0 not enforced (0 judgement, 0 skipped, 0 unverified)"),
        "{out}"
    );
    assert!(
        out.contains(&format!("wrote {}", files[0].display())),
        "{out}"
    );
    assert!(!out.contains("next: saiife policy reload"), "{out}");
    #[cfg(unix)]
    {
        let (c, err) = hook(&env, "deploy-prod --now");
        assert_eq!(c, 2, "{err}");
        assert!(
            err.contains("CLAUDE.md:1 \"Never run `deploy-prod`.\""),
            "{err}"
        );
        assert_eq!(hook(&env, "deploy-prod --help").0, 0);
    }
}

/// The `--help` carve-out never covers `-h` (`shutdown -h now` halts),
/// and lifts only the import's own deny: a built-in deny stays.
#[cfg(unix)]
#[test]
fn carve_out_is_help_only_and_own_pack_only() {
    let env = Env::new(&["claude"]);
    env.write("CLAUDE.md", "Never run `shutdown`.\nNever run `mkfs`.\n");
    let o = rules(&env, &["import", "CLAUDE.md"], "e\n\ne\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.contains(r"(allow ^shutdown\s+(?:--help|--version)$)"),
        "{out}"
    );
    assert!(
        stderr(&o).contains("and (allow ^shutdown"),
        "{}",
        stderr(&o)
    );
    let (c, err) = hook(&env, "shutdown -h now");
    assert_eq!(c, 2, "{err}");
    assert!(err.contains("user.claude-md-"), "{err}");
    assert_eq!(hook(&env, "shutdown --help").0, 0);
    // core.filesystem denies `mkfs` whatever follows: the import's own
    // `mkfs --help` carve-out does not lift it.
    let (c, err) = hook(&env, "mkfs --help");
    assert_eq!(c, 2, "{err}");
    assert!(err.contains("core.filesystem"), "{err}");
}

#[test]
fn import_eof_writes_nothing() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", DEPLOY);
    let o = rules(&env, &["import", "CLAUDE.md"], "");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("stopped before the last rule; nothing written"),
        "{}",
        stderr(&o)
    );
    assert!(pack_files(&personal_packs(&env)).is_empty());
}

#[test]
fn import_all_skipped_writes_nothing() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", DEPLOY);
    let o = rules(&env, &["import", "CLAUDE.md"], "s\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let all = format!("{}{}", stdout(&o), stderr(&o));
    assert!(all.contains("no rule confirmed; nothing written"), "{all}");
    assert!(pack_files(&personal_packs(&env)).is_empty());
}

#[test]
fn second_import_is_refused() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", DEPLOY);
    assert_eq!(code(&rules(&env, &["import", "CLAUDE.md"], "e\n\n")), 0);
    // The same file by another way there is the same source.
    fs::create_dir_all(env.root().join("sub")).unwrap();
    let again = if cfg!(unix) {
        "sub/../CLAUDE.md"
    } else {
        "CLAUDE.md"
    };
    let o = rules(&env, &["import", again], "e\n\n");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("already imported as user.claude-md-"), "{err}");
    assert!(err.contains("; use saiife rules sync"), "{err}");
    assert_eq!(pack_files(&personal_packs(&env)).len(), 1);
}

#[test]
fn default_files_are_found_in_the_project() {
    let env = Env::new(&[]);
    let o = rules(&env, &["import"], "");
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    for n in ["CLAUDE.md", "AGENTS.md", "GEMINI.md"] {
        assert!(stderr(&o).contains(n), "{n}: {}", stderr(&o));
    }
    env.write("AGENTS.md", DEPLOY);
    let o = rules(&env, &["import"], "e\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let files = pack_files(&personal_packs(&env));
    assert_eq!(files.len(), 1);
    assert!(files[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("user.agents-md-"));
}

#[test]
fn bad_name_is_bad_input() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", DEPLOY);
    let o = rules(
        &env,
        &["import", "--name", "Bad_Name", "CLAUDE.md"],
        "e\n\n",
    );
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(pack_files(&personal_packs(&env)).is_empty());
    let o = rules(&env, &["import", "--name", "no-prod", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(personal_packs(&env).join("user.no-prod.toml").is_file());
}

const NEVER_JUDGE: &str = "# Rules\n\nNever destroy the staging infra.\n";

/// A fake `claude` that prints `json` and ignores stdin.
#[cfg(unix)]
fn fake_claude(env: &Env, json: &str) {
    common::fake_exe(
        env.bin.path(),
        "claude",
        &format!("/bin/cat >/dev/null; printf '%s' '{json}'"),
    );
}

#[cfg(unix)]
#[test]
fn llm_pass_adds_verified_rules() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", NEVER_JUDGE);
    fake_claude(
        &env,
        r#"{"rules":[{"kind":"command","line":3,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform plan"]}]}"#,
    );
    let o = rules(&env, &["import", "--llm", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("sending 1 lines of CLAUDE.md to claude -p"),
        "{}",
        stderr(&o)
    );
    let files = pack_files(&personal_packs(&env));
    assert_eq!(files.len(), 1, "{}", stderr(&o));
    let pack = fs::read_to_string(&files[0]).unwrap();
    assert!(pack.contains("terraform"), "{pack}");
    assert!(pack.contains("line = 3"), "{pack}");
    assert!(!pack.contains("[[allow]]"), "{pack}");
    assert!(stdout(&o).contains("0 judgement"), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn llm_bad_rule_is_listed_unverified() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", NEVER_JUDGE);
    fake_claude(
        &env,
        r#"{"rules":[{"kind":"command","line":3,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform destroy -auto-approve"]}]}"#,
    );
    let o = rules(&env, &["import", "--llm", "CLAUDE.md"], "");
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("unverified: llm:"), "{}", stdout(&o));
    assert!(pack_files(&personal_packs(&env)).is_empty());
}

#[test]
fn llm_missing_claude_warns_and_goes_on() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", &format!("{DEPLOY}{NEVER_JUDGE}"));
    let o = rules(&env, &["import", "--llm", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains(
            "warning: claude is not on PATH; the LLM pass needs Claude Code; continuing without the LLM pass"
        ),
        "{}",
        stderr(&o)
    );
    assert_eq!(pack_files(&personal_packs(&env)).len(), 1);
}

#[cfg(unix)]
#[test]
fn llm_timeout_kills_and_goes_on() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", &format!("{DEPLOY}{NEVER_JUDGE}"));
    common::fake_exe(
        env.bin.path(),
        "claude",
        "/bin/cat >/dev/null; exec /bin/sleep 30",
    );
    let absent = common::absent_system_config(env.home.path());
    let start = std::time::Instant::now();
    let mut child = env
        .command_in(env.root(), &["rules", "import", "--llm", "CLAUDE.md"])
        .env("SAIIFE_TEST_SYSTEM_CONFIG", &absent)
        .env("SAIIFE_TEST_LLM_TIMEOUT_MS", "300")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"e\n\n").unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("claude did not answer in 1 s; continuing without the LLM pass"),
        "{}",
        stderr(&o)
    );
    assert_eq!(pack_files(&personal_packs(&env)).len(), 1);
}

#[cfg(unix)]
#[test]
fn llm_huge_output_is_refused() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", &format!("{DEPLOY}{NEVER_JUDGE}"));
    common::fake_exe(
        env.bin.path(),
        "claude",
        "/bin/cat >/dev/null; i=0; while [ $i -lt 300 ]; do printf '%01024d' 0; i=$((i+1)); done",
    );
    let o = rules(&env, &["import", "--llm", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("claude answered more than 256 KiB; continuing without the LLM pass"),
        "{}",
        stderr(&o)
    );
    assert_eq!(pack_files(&personal_packs(&env)).len(), 1);
}

#[cfg(unix)]
#[test]
fn llm_nonzero_exit_quotes_stderr_cleaned() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", &format!("{DEPLOY}{NEVER_JUDGE}"));
    common::fake_exe(
        env.bin.path(),
        "claude",
        "/bin/cat >/dev/null; printf 'login \\033[2J needed' >&2; exit 3",
    );
    let o = rules(&env, &["import", "--llm", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("login ?[2J needed"), "{err}");
    assert!(!err.contains('\u{1b}'), "{err:?}");
}

#[test]
fn over_the_rule_cap_writes_nothing() {
    let env = Env::new(&[]);
    let progs: Vec<String> = (1..=70).map(|i| format!("zzprog{i}")).collect();
    env.write(
        "CLAUDE.md",
        &format!("Never run these: {}.\n", progs.join(", ")),
    );
    let o = rules(&env, &["import", "CLAUDE.md"], &"e\n\n".repeat(70));
    let out = stdout(&o);
    assert!(out.contains("70 proposed"), "{out}");
    assert_eq!(code(&o), 1, "{out}\n{}", stderr(&o));
    assert!(stderr(&o).contains("128"), "{}", stderr(&o));
    assert!(stderr(&o).contains("nothing written"), "{}", stderr(&o));
    assert!(pack_files(&personal_packs(&env)).is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_source_is_refused() {
    let env = Env::new(&[]);
    env.write("real.md", DEPLOY);
    std::os::unix::fs::symlink(env.root().join("real.md"), env.root().join("CLAUDE.md")).unwrap();
    let o = rules(&env, &["import", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("symlink"), "{}", stderr(&o));
    assert!(pack_files(&personal_packs(&env)).is_empty());
}

#[test]
fn escapes_in_the_source_never_reach_the_terminal() {
    let env = Env::new(&[]);
    env.write("CLAUDE.md", "Never run `deploy-prod`. \u{1b}[2J\u{202e}\n");
    let o = rules(&env, &["import", "CLAUDE.md"], "e\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for s in [stdout(&o), stderr(&o)] {
        assert!(!s.contains('\u{1b}') && !s.contains('\u{202e}'), "{s:?}");
    }
}

// ---- import, locked target (a test daemon and --config) ----

#[cfg(unix)]
mod locked {
    use super::*;
    use common::daemon::{own_group, own_user, Opts, TestDaemon};
    use std::process::Command;

    fn admin_with_approver() -> TestDaemon {
        TestDaemon::start(Opts {
            extra: format!(
                "[admin]\ngroups = [{:?}]\n\n[approval]\napprovers = [{:?}]\n",
                own_group(),
                own_user()
            ),
            ..Opts::default()
        })
    }

    fn saiife(d: &TestDaemon, args: &[&str], answers: &str) -> Output {
        let project = d.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(args)
            .arg(if args[0] == "policy" {
                "--system-config"
            } else {
                "--config"
            })
            .arg(d.config())
            .current_dir(&project)
            .env("HOME", d.path().join("home"))
            .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", d.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", d.audit_dir())
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answers.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn import_on_locked_target_offers_ask() {
        use std::os::unix::fs::PermissionsExt;
        let d = admin_with_approver();
        let project = d.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("CLAUDE.md"), "Never run `terraform apply`.\n").unwrap();
        let o = saiife(&d, &["rules", "import", "CLAUDE.md"], "a\n\n");
        assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("ask, "), "{}", stderr(&o));
        let dir = d.path().join("etc/policy.d/packs");
        let files = pack_files(&dir);
        assert_eq!(files.len(), 1, "{files:?}");
        let text = fs::read_to_string(&files[0]).unwrap();
        assert!(text.contains("ask = true"), "{text}");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&files[0]), 0o644);
        assert_eq!(mode(&dir), 0o755);
        let out = stdout(&o);
        assert!(out.contains("1 rules (1 ask)"), "{out}");
        assert!(out.contains("next: saiife policy reload"), "{out}");

        let id = files[0].file_stem().unwrap().to_string_lossy().into_owned();
        let r = saiife(&d, &["policy", "reload"], "");
        assert_eq!(code(&r), 0, "{}\n{}", stdout(&r), stderr(&r));
        assert!(stdout(&r).contains("loaded"), "{}", stdout(&r));
        let s = saiife(&d, &["policy", "show"], "");
        assert_eq!(code(&s), 0, "{}", stderr(&s));
        assert!(stdout(&s).contains(&format!("{id}/l1-1")), "{}", stdout(&s));
    }
}
