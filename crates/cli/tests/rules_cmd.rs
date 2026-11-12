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

// ---- sync ----

fn imported_pack(env: &Env, md: &str, answers: &str) -> PathBuf {
    env.write("CLAUDE.md", md);
    let o = rules(env, &["import", "CLAUDE.md"], answers);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    pack_files(&personal_packs(env)).remove(0)
}

fn sha_of(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn unchanged_source_says_so() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    let before = fs::read(&pack).unwrap();
    let o = rules(&env, &["sync"], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("unchanged"), "{}", stdout(&o));
    assert_eq!(fs::read(&pack).unwrap(), before);
}

#[test]
fn gone_line_kept_by_default() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    env.write("CLAUDE.md", "nothing to see\n");
    let o = rules(&env, &["sync"], "\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("- line 1 gone"), "{out}");
    assert!(out.contains("Never run `deploy-prod`."), "{out}");
    let text = fs::read_to_string(&pack).unwrap();
    assert!(text.contains("deploy-prod"), "{text}");
    assert!(
        text.contains(&format!("sha256 = \"{}\"", sha_of("nothing to see\n"))),
        "{text}"
    );
}

#[test]
fn gone_line_removed_on_r() {
    let env = Env::new(&[]);
    let pack = imported_pack(
        &env,
        "Never run `deploy-prod`.\nNever run `terraform apply`.\n",
        "e\n\ne\n\n",
    );
    env.write("CLAUDE.md", "Never run `terraform apply`.\n");
    let o = rules(&env, &["sync"], "r\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let text = fs::read_to_string(&pack).unwrap();
    // Triggers are never pruned; no rule or carve-out for it is left.
    assert!(!text.contains("^deploy-prod"), "{text}");
    assert!(!text.contains("Never run `deploy-prod`"), "{text}");
    assert!(text.contains("terraform"), "{text}");
    assert!(text.contains("line = 1"), "moved up: {text}");
    // The carve-out `[[allow]]` went with its deny.
    assert!(!text.contains("deploy-prod\\s"), "{text}");
}

#[test]
fn gone_line_removed_last_rule_deletes_the_pack() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    env.write("CLAUDE.md", "nothing\n");
    let o = rules(&env, &["sync"], "r\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains(" removed: no rules left"),
        "{}",
        stdout(&o)
    );
    assert!(stdout(&o).contains("user."), "{}", stdout(&o));
    assert!(!pack.exists());
}

#[test]
fn new_line_is_only_proposed() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    let deny = |t: &str| t.matches("[[deny]]").count();
    let before = deny(&fs::read_to_string(&pack).unwrap());
    env.write("CLAUDE.md", "Never run `deploy-prod`.\nNever run `x2`.\n");
    let o = rules(&env, &["sync"], "s\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("+ line 2: \"Never run `x2`.\""),
        "{}",
        stdout(&o)
    );
    let text = fs::read_to_string(&pack).unwrap();
    assert_eq!(deny(&text), before, "{text}");
    assert!(text.contains("why = \"skipped\""), "{text}");

    // Skipped lines are known now; a new one is enforced on `e`.
    env.write(
        "CLAUDE.md",
        "Never run `deploy-prod`.\nNever run `x2`.\nNever run `x3`.\n",
    );
    let o = rules(&env, &["sync"], "e\n\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let text = fs::read_to_string(&pack).unwrap();
    assert!(text.contains("id = \"l3-1\""), "{text}");
}

#[test]
fn sync_eof_writes_nothing() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    let before = fs::read(&pack).unwrap();
    env.write("CLAUDE.md", "nothing\n");
    let o = rules(&env, &["sync"], "");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(fs::read(&pack).unwrap(), before);
}

#[test]
fn sync_unknown_pack_is_bad_input() {
    let env = Env::new(&[]);
    imported_pack(&env, DEPLOY, "e\n\n");
    let o = rules(&env, &["sync", "--pack", "user.nope"], "");
    assert_eq!(code(&o), 2, "{}", stderr(&o));
}

#[test]
fn sync_missing_source_keeps_rules() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    fs::remove_file(env.root().join("CLAUDE.md")).unwrap();
    let before = fs::read(&pack).unwrap();
    let o = rules(&env, &["sync"], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("source gone; rules kept"),
        "{}",
        stderr(&o)
    );
    assert_eq!(fs::read(&pack).unwrap(), before);
}

#[test]
fn sync_output_never_carries_control_bytes() {
    let env = Env::new(&[]);
    let esc = "Never run `rm\u{1b}[31m` or \u{202e}x.\n";
    imported_pack(&env, &format!("{DEPLOY}{esc}"), "e\n\n");
    env.write("CLAUDE.md", &format!("{DEPLOY}Never run `new\u{1b}[2J`.\n"));
    let o = rules(&env, &["sync"], "\n");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let all = format!("{}{}", stdout(&o), stderr(&o));
    assert!(all.contains("- line 2 gone"), "{all}");
    assert!(
        !all.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t' || c == '\u{202e}'),
        "{all:?}"
    );
}

#[test]
fn sync_stop_after_a_write_says_what_was_written() {
    let env = Env::new(&[]);
    env.write("AGENTS.md", DEPLOY);
    env.write("CLAUDE.md", "Never run `terraform apply`.\n");
    for f in ["AGENTS.md", "CLAUDE.md"] {
        let o = rules(&env, &["import", f], "e\n\n");
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    }
    let files = pack_files(&personal_packs(&env));
    assert_eq!(files.len(), 2);
    let (p1, p2) = (&files[0], &files[1]);
    assert!(p1.file_name().unwrap().to_string_lossy().contains("agents"));
    let (b1, b2) = (fs::read(p1).unwrap(), fs::read(p2).unwrap());
    env.write("AGENTS.md", "gone\n");
    env.write("CLAUDE.md", "gone too\n");
    // The first pack's one question is answered (keep); input ends at the second.
    let o = rules(&env, &["sync"], "\n");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    let id1 = p1.file_stem().unwrap().to_string_lossy().into_owned();
    assert!(err.contains("earlier packs updated:"), "{err}");
    assert!(err.contains(&id1), "{err}");
    assert!(err.contains("this and later packs unchanged"), "{err}");
    assert!(!err.contains("nothing written"), "{err}");
    assert_ne!(fs::read(p1).unwrap(), b1);
    assert_eq!(fs::read(p2).unwrap(), b2);
}

// ---- list ----

const MIXED: &str = "Never run `deploy-prod`.\nNever run `terraform apply`.\nNever write to `~/billing`.\nNever skip the tests.\n";

#[test]
fn list_shows_host_and_box_status() {
    let env = Env::new(&[]);
    imported_pack(&env, MIXED, "e\n\ne\nh\ne\n\n");
    let o = rules(&env, &[], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    for want in [
        "box: advisory in boxes",
        "box: off in boxes (host only)",
        "box: checked at diff review",
        "where=host",
        "where=everywhere",
        "host: enforced",
        "not enforced: ",
        "CLAUDE.md:4",
        "\"Never skip the tests.\"",
        "CLAUDE.md  5 rules (0 ask), 1 not enforced",
    ] {
        assert!(out.contains(want), "{want:?} missing:\n{out}");
    }
    assert!(!out.contains("source changed"), "{out}");
    let j = rules(&env, &["list"], "");
    assert_eq!(stdout(&j), out);
}

#[test]
fn list_json_shape() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    let o = rules(&env, &["list", "--json"], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let got: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let id = pack.file_stem().unwrap().to_string_lossy().into_owned();
    let file = fs::canonicalize(env.root().join("CLAUDE.md"))
        .unwrap()
        .display()
        .to_string();
    let p = &got["packs"][0];
    assert_eq!(got["packs"].as_array().unwrap().len(), 1);
    assert_eq!(p["id"], id);
    assert_eq!(p["path"], pack.display().to_string());
    assert_eq!(p["import"]["file"], file);
    assert_eq!(p["import"]["sha256"], sha_of(DEPLOY));
    assert_eq!(p["import"]["state"], "same");
    assert_eq!(p["unenforced"], serde_json::json!([]));
    let r = &p["rules"];
    assert_eq!(r.as_array().unwrap().len(), 2, "{got}");
    // The carve-out comes first, then the deny.
    assert_eq!(r[0]["kind"], "allow");
    assert_eq!(r[1]["id"], "l1-1");
    assert_eq!(r[1]["kind"], "deny");
    assert_eq!(r[1]["where"], "everywhere");
    assert_eq!(r[1]["mode"], "enforce");
    assert_eq!(r[1]["host"], "enforced");
    assert_eq!(r[1]["box"], "advisory in boxes");
    assert_eq!(r[1]["source"]["line"], 1);
    assert_eq!(r[1]["source"]["file"], file);
    assert_eq!(r[1]["text"], r"^deploy\-prod(?:\s|$)");
    // Exactly the documented keys.
    let keys = |v: &serde_json::Value| -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&got), ["packs"]);
    assert_eq!(keys(p), ["id", "import", "path", "rules", "unenforced"]);
    assert_eq!(
        keys(&r[1]),
        ["box", "host", "id", "kind", "mode", "source", "text", "where"]
    );
}

#[test]
fn list_flags_broad_rules() {
    let env = Env::new(&[]);
    // `ls` is an everyday command: a typed `yes` enforces it anyway.
    imported_pack(&env, "Never run `ls`.\n", "e\nyes\n\n");
    let o = rules(&env, &[], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("BROAD: blocks everyday `ls`")
            || stdout(&o).contains("BROAD: blocks everyday"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn list_with_no_packs_says_so() {
    let env = Env::new(&[]);
    let o = rules(&env, &[], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("no user packs"), "{}", stdout(&o));
}

#[test]
fn list_marks_changed_and_gone_sources() {
    let env = Env::new(&[]);
    imported_pack(&env, DEPLOY, "e\n\n");
    env.write("CLAUDE.md", &format!("{DEPLOY}Never run `x`.\n"));
    let o = rules(&env, &[], "");
    assert!(
        stdout(&o).contains("[source changed: run saiife rules sync]"),
        "{}",
        stdout(&o)
    );
    fs::remove_file(env.root().join("CLAUDE.md")).unwrap();
    let o = rules(&env, &[], "");
    assert!(stdout(&o).contains("[source gone]"), "{}", stdout(&o));
}

/// A hand-edited pack with escape and bidi characters: nothing raw reaches
/// the terminal in text mode.
#[test]
fn list_output_never_carries_control_bytes() {
    let env = Env::new(&[]);
    let pack = imported_pack(&env, DEPLOY, "e\n\n");
    let text = fs::read_to_string(&pack).unwrap();
    let text = text
        .replace("reason = \"", "reason = \"a\\u001b[2Jb\\u202ec")
        .replace("text = \"", "text = \"a\\u001b[31m\\u202e");
    fs::write(&pack, &text).unwrap();
    let o = rules(&env, &[], "");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let all = format!("{}{}", stdout(&o), stderr(&o));
    assert!(
        !all.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t' || c == '\u{202e}'),
        "{all:?}"
    );
}
