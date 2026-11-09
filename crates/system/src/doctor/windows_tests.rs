//! Doctor against a Windows tree on Linux: a real run of Windows install through
//! [`FakeHost`], then what each check says of what is there. Nothing here has run on Windows.
//! On Unix only, as in `install_win`: it builds the tree on a Unix filesystem and plants
//! Unix links.

use super::*;
use crate::binary::tests::{pe_fixture, PeFixture};
use crate::doctor::{run, DoctorOptions, Report, Status};
use crate::host::{FakeHost, RegValue};
use crate::install::{install_locked, lock_install, InstallOptions};
use crate::winservice::{SidType, StartKind};
use saiife_agents::Agent;
use saiife_policy::installed::{read_installed, write_installed};
use saiife_policy::FixedDirectory;
use saiife_win::sddl::stock;
use saiife_win::sid::{service_sid, ADMINISTRATORS};
use serde_json::{json, Map};
use std::fs;
use std::path::PathBuf;

const USER: &str = "S-1-5-21-9-9-9-1001";
const ALICE: &str = "alice";
const SYSTEM_CONFIG_USERS: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n";

fn canned(stdout: &str, status: i32) -> crate::host::CmdOutput {
    crate::host::CmdOutput {
        status,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

fn answer() -> Map<String, serde_json::Value> {
    json!({"policy_ok": true, "chain": "ok", "head_seq": 7, "last_checkpoint_seq": 6,
        "cosign": whole_cosign(),
        "hooks_no_verdict": {"since_start": 0, "last_ts": null},
        "hooks_rejudge_denied": {"since_start": 0, "last_ts": null}})
    .as_object()
    .unwrap()
    .clone()
}

/// A co-signer that listens, judges each call itself, and knows who asks (plan 21).
fn whole_cosign() -> serde_json::Value {
    json!({"addr": "127.0.0.1:7433", "error": null, "asker": "tcp_table",
        "rejudge": {"workers": 2, "error": null}})
}

struct Env {
    _dir: tempfile::TempDir,
    layout: Layout,
    host: FakeHost,
    binary: PathBuf,
}

/// A stock, elevated Windows machine below a temp dir, with nothing installed.
fn stock_machine(pe: PeFixture) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::under_for(dir.path(), Platform::Windows);
    let host = FakeHost::open(layout.root()).unwrap();
    let root = layout.root().to_path_buf();
    for (p, sd) in [
        ("C", stock::DRIVE_ROOT),
        ("C/ProgramData", stock::PROGRAM_DATA),
        ("C/Program Files", stock::PROGRAM_FILES),
    ] {
        let real = root.join(p);
        fs::create_dir_all(&real).unwrap();
        host.set(|s| {
            s.sddl.insert(real.clone(), sd.to_string());
        });
    }
    host.set(|s| {
        s.euid = 0;
        s.net = true;
    });
    let binary = root.join("incoming.exe");
    fs::write(&binary, pe_fixture(pe)).unwrap();
    Env {
        _dir: dir,
        layout,
        host,
        binary,
    }
}

impl Env {
    fn at(&self, logical: &str) -> PathBuf {
        self.layout.try_at(Path::new(logical)).unwrap()
    }

    fn install(&self, agents: &[Agent]) {
        let opts = InstallOptions {
            config: None,
            agents: agents.to_vec(),
            approvers: Vec::new(),
            non_interactive: true,
            // The fixture has no import the real allowlist would refuse; a test that wants
            // a refused binary swaps the file afterwards.
            allow_test_build: false,
        };
        let lock = lock_install(&self.layout, &self.host).unwrap();
        let began = std::cell::Cell::new(false);
        install_locked(&lock, &self.layout, &self.host, &opts, &self.binary, &began).unwrap();
        drop(lock);
        self.read_back_as_windows();
    }

    /// The fake hands back what was set. Windows keeps no `OI` or `CI` on a file (seen in
    /// CI on `saiife.exe`), which is what doctor reads.
    fn read_back_as_windows(&self) {
        self.host.set(|s| {
            for (path, sddl) in s.sddl.iter_mut() {
                if path.is_file() {
                    *sddl = sddl.replace(";OICI;", ";;");
                }
            }
        });
    }

    fn doctor_as(&self, user: Option<&str>) -> Report {
        run(
            &self.layout,
            &self.host,
            &FixedDirectory::from_text(SYSTEM_CONFIG_USERS, ""),
            &DoctorOptions {
                user: user.map(str::to_string),
                home: None,
            },
        )
    }

    fn doctor(&self) -> Report {
        self.doctor_as(None)
    }

    fn sddl(&self, logical: &str) -> String {
        self.host.state().sddl[&self.at(logical)].clone()
    }

    fn set_sddl(&self, logical: &str, text: &str) {
        let p = self.at(logical);
        self.host.set(|s| {
            s.sddl.insert(p.clone(), text.to_string());
        });
    }

    /// A file below the tree, with a descriptor on record.
    fn plant(&self, logical: &str, text: &str) {
        let p = self.at(logical);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"x").unwrap();
        self.set_sddl(logical, text);
    }

    fn edit_live(&self, edit: impl FnOnce(&mut crate::winservice::ServiceSpec)) {
        self.host
            .set(|s| edit(s.services.get_mut(WIN_SERVICE).unwrap()));
    }

    fn uac(&self, consent: u32, secure_desktop: u32, lua: u32) {
        self.host.set(|s| {
            for (value, v) in [
                ("ConsentPromptBehaviorAdmin", consent),
                ("PromptOnSecureDesktop", secure_desktop),
                ("EnableLUA", lua),
            ] {
                s.registry
                    .insert((REG_UAC.to_string(), value.to_string()), RegValue::Dword(v));
            }
        });
    }

    /// An agent user in these groups, by the names this machine gives them.
    fn user_in(&self, name: &str, sid: &str, groups: &[(&str, &str)]) {
        self.host.set(|s| {
            s.sids.insert(name.to_string(), sid.to_string());
            s.local_groups.insert(
                name.to_string(),
                groups.iter().map(|(g, _)| g.to_string()).collect(),
            );
            for (g, gsid) in groups {
                s.sids.insert(g.to_string(), gsid.to_string());
            }
        });
    }

    /// The daemon makes this at its first start, which a fake install has none of.
    fn audit_key_as_the_daemon_left_it(&self) {
        let s = service_sid(WIN_SERVICE);
        self.plant(
            AUDIT_KEY_FILE,
            &format!("O:{s}G:{s}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{s})"),
        );
        fs::write(self.at(AUDIT_KEY_FILE), [7u8; 32]).unwrap();
    }

    /// Doctor's verdict on one check.
    fn status(&self, r: &Report, id: &str) -> Status {
        get(r, id).status
    }
}

/// A healthy install, the daemon answering, with every agent.
fn installed() -> Env {
    let e = stock_machine(PeFixture::default());
    e.install(&Agent::ALL);
    e.host.set(|s| {
        s.daemon_status = Some(answer());
        s.authenticode = Some(0);
    });
    e.audit_key_as_the_daemon_left_it();
    e
}

fn get<'r>(r: &'r Report, id: &str) -> &'r Check {
    r.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id} in\n{}", r.to_text()))
}

fn failed(r: &Report) -> Vec<&str> {
    r.checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .map(|c| c.id.as_str())
        .collect()
}

fn user_owned() -> String {
    format!("O:{USER}G:{USER}D:(A;OICI;FA;;;{USER})")
}

const ROOT: &str = r"C:\ProgramData\saiife";
const EXE: &str = r"C:\ProgramData\saiife\bin\saiife.exe";
const CONFIG_FILE: &str = r"C:\ProgramData\saiife\etc\config.toml";
const KEY: &str = r"C:\ProgramData\saiife\state\keys\vault.key";
const AUDIT_KEY_FILE: &str = r"C:\ProgramData\saiife\state\keys\audit.ed25519";
const STATE_DB: &str = r"C:\ProgramData\saiife\state\sessions.db";
const DROP_IN: &str = r"C:\ProgramData\saiife\etc\policy.d\10-admin.toml";
const MCP: &str = r"C:\Program Files\ClaudeCode\managed-settings.d\60-saiife-mcp.json";
const GEMINI: &str = r"C:\ProgramData\gemini-cli";
const CLAUDE_SETTINGS: &str = r"C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json";

// ----------------------------------------------------------------- the whole run

#[test]
fn windows_doctor_after_fake_install_fails_only_daemon_checks() {
    let e = installed();
    e.host.set(|s| s.daemon_status = None);
    let r = e.doctor();
    assert_eq!(failed(&r), ["daemon.health"], "{}", r.to_text());
    assert!(get(&r, "daemon.health").detail.contains("did not answer"));

    // With the daemon answering nothing fails, and what still warns is the preview's
    // labels: no Windows recording yet.
    e.host.set(|s| s.daemon_status = Some(answer()));
    let r = e.doctor();
    assert_eq!(failed(&r), Vec::<&str>::new(), "{}", r.to_text());
    for id in [
        "files.acl",
        "files.installed",
        "files.binary",
        "daemon.unit",
    ] {
        assert_eq!(e.status(&r, id), Status::Pass, "{id}: {}", r.to_text());
    }
    assert_eq!(
        get(&r, "daemon.health").detail,
        "chain ok, head seq 7, last checkpoint seq 6"
    );
    assert_eq!(r.exit_code(), 1);
    assert_eq!(e.status(&r, "agents.claude.label"), Status::Warn);
}

/// Every id the Windows brief fixes, and nothing the Unix checks would read wrongly.
#[test]
fn every_windows_check_id_is_there_and_no_unix_one() {
    let r = installed().doctor();
    for id in [
        "system.supported",
        "install.record",
        "config.valid",
        "daemon.unit",
        "daemon.health",
        "files.binary",
        "files.acl",
        "files.installed",
        "keys",
        "vault.key",
        "reauth",
        "peer.pidfd",
        "agents.claude.policy",
        "mcp.landlock",
        "mcp.claude.allowlist",
        "disk.encryption",
        "locked.preview",
        "forwarding",
        "cosign.listen",
        "cosign.rejudge",
        "cosign.asker",
        "hooks.rejudge-denied",
    ] {
        get(&r, id);
    }
    for id in ["paths.owner", "files.modes", "daemon.group"] {
        assert!(!r.checks.iter().any(|c| c.id == id), "{id}");
    }
}

#[test]
fn info_lines_say_what_the_brief_fixes() {
    let r = installed().doctor();
    let says = |id: &str, want: &str| {
        let c = get(&r, id);
        assert_eq!(c.status, Status::Info, "{id}");
        let text = if c.detail.is_empty() {
            &c.title
        } else {
            &c.detail
        };
        assert_eq!(text, want, "{id}");
    };
    says(
        "vault.key",
        r"daemon key file, readable only by NT SERVICE\saiifed",
    );
    says(
        "peer.pidfd",
        "named pipe; caller identity from its token (the pid is used for attribution only)",
    );
    says("mcp.landlock", "MCP gateway: Linux only in this version");
    says(
        "disk.encryption",
        "see docs/windows.md#disk-encryption for BitLocker",
    );
    // W16 as the owner ruling rewrote it: no password text.
    says(
        "reauth",
        "same-user approval is off on Windows: approvals need a second account, from a \
         separate session",
    );
}

/// What the lock does not do must be said, in a line that fails nothing. With the
/// co-signer whole, Claude Code is no preview, and the line names the other two.
#[test]
fn the_preview_limits_are_said_and_fail_nothing() {
    let c = as_alice(&installed());
    let c = get(&c, "locked.preview");
    assert_eq!(c.status, Status::Info);
    for word in [
        "a preview for Codex and Gemini CLI",
        "exit 0",
        "reads as allow",
        "recorded, not prevented",
        "unverified",
        "Claude Code is not",
        "judged by the hook and by the service",
        "docs/windows.md#locked-mode",
    ] {
        assert!(c.detail.contains(word), "{word}: {}", c.detail);
    }
    // Only CI has run it, and it must not claim more.
    assert!(!c.detail.contains("tested by hand"), "{}", c.detail);
    assert!(!c.detail.contains("has not been tested"), "{}", c.detail);
}

/// A Windows install with only these agents, and this `status` answer.
fn with_agents(agents: &[Agent], status: Map<String, serde_json::Value>) -> Env {
    let e = stock_machine(PeFixture::default());
    e.install(agents);
    e.host.set(|s| {
        s.daemon_status = Some(status);
        s.authenticode = Some(0);
    });
    e.audit_key_as_the_daemon_left_it();
    e
}

/// `answer()` with one field of `status.cosign` set to `v`.
fn cosign_field(field: &str, v: serde_json::Value) -> Map<String, serde_json::Value> {
    let mut c = whole_cosign();
    c.as_object_mut().unwrap().insert(field.into(), v);
    let mut a = answer();
    a.insert("cosign".into(), c);
    a
}

/// `answer()` with `status.cosign.<field>` absent (an older daemon).
fn cosign_without(field: &str) -> Map<String, serde_json::Value> {
    let mut c = whole_cosign();
    c.as_object_mut().unwrap().remove(field);
    let mut a = answer();
    a.insert("cosign".into(), c);
    a
}

/// Doctor run by alice from her own plain shell, her `claude.exe` new enough: the one run
/// that shows Claude Code's version.
fn as_alice(e: &Env) -> Report {
    claude_exe(e, Some(("2.1.300 (Claude Code)\n", 0)));
    e.host.set(|s| s.euid = 1000);
    e.doctor_as(Some(ALICE))
}

#[test]
fn preview_absent_for_claude_only_when_cosign_is_whole() {
    let r = as_alice(&with_agents(&[Agent::Claude], answer()));
    let c = get(&r, "locked.preview");
    assert_eq!(c.status, Status::Pass, "{}", r.to_text());
    assert_eq!(
        c.detail,
        "Windows locked mode for Claude Code: each call is judged by the hook and by the service"
    );
    assert!(!c.detail.contains("preview"), "{}", c.detail);
    assert_eq!(failed(&r), Vec::<&str>::new(), "{}", r.to_text());
}

#[test]
fn preview_names_codex_and_gemini() {
    // Both, with Claude Code: they are named, Claude Code is not a preview.
    let c = get(&as_alice(&installed()), "locked.preview").clone();
    assert_eq!(c.status, Status::Info);
    assert!(
        c.detail.starts_with(
            "Windows locked mode is a preview for Codex and Gemini CLI: a process of the \
             agent's user can end their hook with exit 0"
        ),
        "{}",
        c.detail
    );
    assert!(!c.detail.contains("TerminateProcess"), "{}", c.detail);
    // Only the installed ones are named.
    let c = get(
        &with_agents(&[Agent::Codex], answer()).doctor(),
        "locked.preview",
    )
    .clone();
    assert_eq!(c.status, Status::Info);
    assert!(
        c.detail
            .starts_with("Windows locked mode is a preview for Codex: "),
        "{}",
        c.detail
    );
    assert!(!c.detail.contains("Gemini"), "{}", c.detail);
    // Without Claude Code, nothing is said of it.
    assert!(!c.detail.contains("Claude Code"), "{}", c.detail);
    let c = get(
        &with_agents(&[Agent::Gemini], answer()).doctor(),
        "locked.preview",
    )
    .clone();
    assert!(
        c.detail
            .starts_with("Windows locked mode is a preview for Gemini CLI: "),
        "{}",
        c.detail
    );
}

/// Whole-branch review, F2: the co-signer can be whole while Claude Code never calls it.
/// An HKLM policy that overrides or weakens the drop-in, a drop-in without the HTTP hook,
/// or a Claude Code too old for it each keeps Claude Code a preview.
#[test]
fn preview_kept_when_claude_does_not_call_the_cosigner() {
    let preview = |r: &Report| {
        let c = get(r, "locked.preview").clone();
        assert_eq!(c.status, Status::Info, "{}", r.to_text());
        assert_eq!(c.detail, PREVIEW_LIMITS, "{}", r.to_text());
    };
    // The control: whole, and Pass.
    let e = with_agents(&[Agent::Claude], answer());
    assert_eq!(get(&as_alice(&e), "locked.preview").status, Status::Pass);
    // HKLM overrides the drop-in, or merges one that drops the hooks.
    for settings in [
        r#"{"permissions":{"deny":[]}}"#,
        r#"{"managedSourcesBehavior":"merge","disableAllHooks":true}"#,
    ] {
        let e = with_agents(&[Agent::Claude], answer());
        hklm(&e, settings);
        preview(&as_alice(&e));
    }
    // A drop-in without the co-signer's HTTP hook.
    let e = with_agents(&[Agent::Claude], answer());
    let old = saiife_agents::claude::managed_settings_for(true).replace(
        "http://127.0.0.1:7433/v1/cosign/claude",
        "http://127.0.0.1:7433/elsewhere",
    );
    fs::write(e.at(CLAUDE_SETTINGS), old).unwrap();
    let r = as_alice(&e);
    assert_eq!(get(&r, "agents.claude.policy").status, Status::Fail);
    preview(&r);
    // A Claude Code older than the minimum, or one whose version cannot be read.
    for out in [("2.0.1\n", 0), ("2.1.300", 1)] {
        let e = with_agents(&[Agent::Claude], answer());
        claude_exe(&e, Some(out));
        e.host.set(|s| s.euid = 1000);
        preview(&e.doctor_as(Some(ALICE)));
    }
    // With Codex and Gemini CLI too, Claude Code is not said to be out of the preview.
    let e = installed();
    hklm(&e, r#"{"permissions":{"deny":[]}}"#);
    preview(&as_alice(&e));
}

/// A version no check showed (an elevated doctor never runs the agent) is no pass: Info,
/// with how to show it.
#[test]
fn preview_kept_until_the_claude_version_is_shown() {
    let r = with_agents(&[Agent::Claude], answer()).doctor();
    let c = get(&r, "locked.preview");
    assert_eq!(c.status, Status::Info, "{}", r.to_text());
    assert!(c.detail.starts_with(PREVIEW_LIMITS), "{}", c.detail);
    assert!(c.detail.contains("--user"), "{}", c.detail);
    // Run as alice, but no claude.exe found: still not shown.
    let e = with_agents(&[Agent::Claude], answer());
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| s.euid = 1000);
    let c = get(&e.doctor_as(Some(ALICE)), "locked.preview").clone();
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("--user"), "{}", c.detail);
}

/// The old text, and Info, when any part of the co-signer is not whole: Claude Code is
/// then a preview too.
#[test]
fn preview_kept_when_rejudge_fails() {
    let broken = [
        cosign_field(
            "rejudge",
            json!({"workers": 0, "error": "no re-judge pool"}),
        ),
        cosign_without("rejudge"),
        cosign_field("asker", serde_json::Value::Null),
        cosign_without("asker"),
        cosign_field("addr", serde_json::Value::Null),
    ];
    for status in broken {
        for agents in [&[Agent::Claude][..], &Agent::ALL[..]] {
            let r = with_agents(agents, status.clone()).doctor();
            let c = get(&r, "locked.preview");
            assert_eq!(c.status, Status::Info, "{status:?}");
            assert_eq!(c.detail, PREVIEW_LIMITS, "{status:?}");
        }
    }
    // No answer at all: nothing says the co-signer is whole.
    let e = with_agents(&[Agent::Claude], answer());
    e.host.set(|s| s.daemon_status = None);
    let c = get(&e.doctor(), "locked.preview").clone();
    assert_eq!(
        (c.status, c.detail.as_str()),
        (Status::Info, PREVIEW_LIMITS)
    );
}

#[test]
fn rejudge_fail_check() {
    let c = get(&installed().doctor(), "cosign.rejudge").clone();
    assert_eq!(c.status, Status::Pass);
    assert_eq!(
        c.detail,
        "the service judges each Claude Code call itself (2 workers)"
    );
    let down = cosign_field(
        "rejudge",
        json!({"workers": 0, "error": "the re-judge pool could not start"}),
    );
    let r = with_agents(&Agent::ALL, down).doctor();
    let c = get(&r, "cosign.rejudge");
    assert_eq!(c.status, Status::Fail);
    assert_eq!(
        c.detail,
        "the service cannot judge Claude Code calls (the re-judge pool could not start), so \
         every call is blocked"
    );
    let r = with_agents(&Agent::ALL, cosign_without("rejudge")).doctor();
    let c = get(&r, "cosign.rejudge");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("an older daemon?"), "{}", c.detail);
    // No worker right now and no error: a warning, never a pass.
    let idle = cosign_field("rejudge", json!({"workers": 0, "error": null}));
    let c = get(&with_agents(&Agent::ALL, idle).doctor(), "cosign.rejudge").clone();
    assert_eq!(c.status, Status::Warn, "{c:?}");
    // Without Claude Code there is nothing to judge.
    let c = get(
        &with_agents(&[Agent::Codex], cosign_without("rejudge")).doctor(),
        "cosign.rejudge",
    )
    .clone();
    assert_eq!(c.status, Status::Info);
}

#[test]
fn asker_fail_check() {
    let c = get(&installed().doctor(), "cosign.asker").clone();
    assert_eq!(c.status, Status::Pass);
    assert!(c.detail.contains("tcp_table"), "{}", c.detail);
    let r = with_agents(&Agent::ALL, cosign_field("asker", serde_json::Value::Null)).doctor();
    let c = get(&r, "cosign.asker");
    assert_eq!(c.status, Status::Fail);
    assert_eq!(
        c.detail,
        "the co-signer cannot tell who asks (GetExtendedTcpTable gave no owner pid for the \
         service's own test connection), so every Claude Code call is blocked"
    );
    let r = with_agents(&Agent::ALL, cosign_without("asker")).doctor();
    let c = get(&r, "cosign.asker");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("an older daemon?"), "{}", c.detail);
    // Another system's source is no pass here.
    let r = with_agents(&Agent::ALL, cosign_field("asker", json!("proc_net"))).doctor();
    assert_eq!(get(&r, "cosign.asker").status, Status::Fail);
    let c = get(
        &with_agents(&[Agent::Gemini], cosign_without("asker")).doctor(),
        "cosign.asker",
    )
    .clone();
    assert_eq!(c.status, Status::Info);
    // No answer: daemon.health fails, and these say they could not look.
    let e = installed();
    e.host.set(|s| s.daemon_status = None);
    let r = e.doctor();
    for id in ["cosign.asker", "cosign.rejudge", "hooks.rejudge-denied"] {
        assert_eq!(get(&r, id).status, Status::Info, "{id}");
    }
}

#[test]
fn rejudge_denied_warns_with_count() {
    let mut a = answer();
    a.insert(
        "hooks_rejudge_denied".into(),
        json!({"since_start": 2, "last_ts": "2026-11-09T10:00:00Z"}),
    );
    let c = get(
        &with_agents(&Agent::ALL, a).doctor(),
        "hooks.rejudge-denied",
    )
    .clone();
    assert_eq!(c.status, Status::Warn);
    assert_eq!(
        c.detail,
        "2 call(s) the hook allowed were denied by the service's own judgment (last \
         2026-11-09T10:00:00Z): a forged verdict, or a guard difference; see saiife audit \
         --kind hook"
    );
    assert_eq!(
        get(&installed().doctor(), "hooks.rejudge-denied").status,
        Status::Pass
    );
    let mut old = answer();
    old.remove("hooks_rejudge_denied");
    let c = get(
        &with_agents(&Agent::ALL, old).doctor(),
        "hooks.rejudge-denied",
    )
    .clone();
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains("an older daemon?"), "{}", c.detail);
}

/// The plan 19b text, kept for when the co-signer is not whole. Since plan 20 a killed
/// hook is recorded (`no_verdict`), so the text no longer says nothing is.
#[test]
fn the_old_preview_limits_are_kept() {
    let r = with_agents(&Agent::ALL, cosign_field("asker", serde_json::Value::Null)).doctor();
    let c = get(&r, "locked.preview");
    assert_eq!(c.status, Status::Info);
    assert!(
        c.detail.starts_with("Windows locked mode is a preview:"),
        "{}",
        c.detail
    );
    for word in [
        "preview",
        "TerminateProcess(hook, 0)",
        "reads as allow",
        "no_verdict",
        "recorded, not prevented",
        "measured in CI",
        "unverified",
        "Codex",
        "Gemini",
        "docs/windows.md#locked-mode",
    ] {
        assert!(c.detail.contains(word), "{word}: {}", c.detail);
    }
    assert!(!c.detail.contains("nothing is recorded"), "{}", c.detail);
    // Only CI has run it, and it must not claim more.
    assert!(!c.detail.contains("tested by hand"), "{}", c.detail);
    assert!(!c.detail.contains("has not been tested"), "{}", c.detail);
}

#[test]
fn windows_doctor_json_exit_codes() {
    // Nothing installed: developer mode, exit 0.
    let e = stock_machine(PeFixture::default());
    let json = e.doctor().to_json();
    assert_eq!(json["saiife_doctor"], 1);
    assert_eq!(json["exit"], 0);

    // Installed and sound: labels warn, exit 1.
    let e = installed();
    let json = e.doctor().to_json();
    assert_eq!(json["exit"], 1, "{json}");
    let ids: Vec<&str> = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"files.acl"), "{ids:?}");

    // A failure, exit 2: what `system install` turns into exit 1.
    e.host.set(|s| s.daemon_status = None);
    let r = e.doctor();
    assert_eq!(r.to_json()["exit"], 2);
    assert_eq!(r.exit_code(), 2);
}

// ----------------------------------------------------------------- not installed

#[test]
fn nothing_installed_reads_as_developer_mode() {
    let r = stock_machine(PeFixture::default()).doctor();
    assert_eq!(get(&r, "install.record").status, Status::Info);
    assert_eq!(r.exit_code(), 0, "{}", r.to_text());
}

/// A deleted record must not read as "not installed" while the service still runs.
#[test]
fn a_service_with_no_record_fails() {
    let e = installed();
    fs::remove_file(e.at(r"C:\ProgramData\saiife\etc\installed.toml")).unwrap();
    let r = e.doctor();
    assert_eq!(get(&r, "install.record").status, Status::Fail);
    assert!(get(&r, "install.record").detail.contains(WIN_SERVICE));
}

#[test]
fn an_unreadable_record_fails() {
    let e = installed();
    fs::write(
        e.at(r"C:\ProgramData\saiife\etc\installed.toml"),
        "not toml [",
    )
    .unwrap();
    let r = e.doctor();
    assert_eq!(get(&r, "install.record").status, Status::Fail, "{r:?}");
    assert!(failed(&r).contains(&"daemon.unit"));
}

// ----------------------------------------------------------------- elevation

/// W26 is about the caller: a plain shell must not say the machine is unsupported.
#[test]
fn a_plain_shell_is_no_unsupported_machine() {
    let e = stock_machine(PeFixture::default());
    e.host.set(|s| s.euid = 1000);
    let r = e.doctor();
    assert_eq!(get(&r, "system.supported").status, Status::Pass);
    assert!(!r.to_text().contains("not supported"), "{}", r.to_text());
    assert_eq!(r.exit_code(), 0);
}

/// `state` denies a plain user, so a plain shell has seen only part of the lock. It says
/// so, and can never exit 0.
#[test]
fn a_plain_shell_says_what_it_did_not_see_and_never_exits_0() {
    let e = installed();
    let denied = [
        e.at(r"C:\ProgramData\saiife\state"),
        e.at(r"C:\ProgramData\saiife\state\keys"),
        e.at(KEY),
    ];
    e.host.set(|s| {
        s.euid = 1000;
        s.sddl_denied = denied.to_vec();
    });
    let r = e.doctor();
    let c = get(&r, "doctor.elevation");
    assert_eq!(c.status, Status::Warn);
    assert!(
        c.detail
            .contains("run this from an elevated terminal (Run as administrator)"),
        "{}",
        c.detail
    );
    let acl = get(&r, "files.acl");
    assert_eq!(acl.status, Status::Info, "{}", r.to_text());
    assert!(acl.detail.contains("not checked"), "{}", acl.detail);
    assert_eq!(get(&r, "vault.key").status, Status::Info);
    assert!(get(&r, "vault.key").detail.contains("not checked"));
    assert_ne!(r.exit_code(), 0);

    // A problem it can see is still a failure.
    e.set_sddl(EXE, &user_owned());
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);
}

/// An elevated doctor that cannot read a descriptor has no excuse.
#[test]
fn an_elevated_doctor_fails_what_it_cannot_read() {
    let e = installed();
    let p = e.at(KEY);
    e.host.set(|s| s.sddl_denied = vec![p.clone()]);
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Fail, "{}", r.to_text());
    assert_eq!(get(&r, "vault.key").status, Status::Fail);
}

/// A low-integrity child of an elevated admin holds `Administrators` and cannot use it.
#[test]
fn a_limited_token_is_a_plain_shell() {
    let e = installed();
    e.host.set(|s| s.limited_token = true);
    assert_eq!(
        get(&e.doctor(), "doctor.elevation").status,
        Status::Warn,
        "uid 0 is not enough"
    );
}

#[test]
fn an_elevated_doctor_has_no_elevation_line() {
    let r = installed().doctor();
    assert!(!r.checks.iter().any(|c| c.id == "doctor.elevation"));
}

// ----------------------------------------------------------------- files.acl

#[test]
fn acl_drift_fails_files_acl() {
    let extra = "(A;;FA;;;BU)";
    for logical in [
        ROOT,
        EXE,
        r"C:\ProgramData\saiife\bin",
        r"C:\ProgramData\saiife\etc",
        CONFIG_FILE,
        r"C:\ProgramData\saiife\etc\policy.d",
        r"C:\ProgramData\saiife\state",
        r"C:\ProgramData\saiife\state\keys",
        KEY,
        r"C:\ProgramData\saiife\log",
        r"C:\ProgramData\saiife\log\audit",
        r"C:\ProgramData\saiife\log\daemon",
        r"C:\ProgramData\saiife\log\daemon\daemon.log",
        r"C:\Program Files\ClaudeCode",
        r"C:\Program Files\ClaudeCode\managed-settings.d",
        CLAUDE_SETTINGS,
        MCP,
        r"C:\ProgramData\OpenAI\Codex\requirements.toml",
        r"C:\ProgramData\gemini-cli\settings.json",
    ] {
        let e = installed();
        let drifted = format!("{}{extra}", e.sddl(logical));
        e.set_sddl(logical, &drifted);
        let r = e.doctor();
        let c = get(&r, "files.acl");
        assert_eq!(c.status, Status::Fail, "{logical}: {}", r.to_text());
        assert!(c.detail.contains(logical), "{logical}: {}", c.detail);
    }
}

#[test]
fn a_missing_path_of_the_table_fails() {
    for logical in [
        r"C:\ProgramData\saiife\state\keys\vault.key",
        AUDIT_KEY_FILE,
        r"C:\ProgramData\saiife\log\daemon\daemon.log",
        CONFIG_FILE,
        EXE,
    ] {
        let e = installed();
        fs::remove_file(e.at(logical)).unwrap();
        let c = e.doctor();
        let c = get(&c, "files.acl");
        assert_eq!(c.status, Status::Fail, "{logical}");
        assert!(c.detail.contains("missing"), "{logical}: {}", c.detail);
    }
}

/// The ruling: who can really write decides below `etc`. An admin's file reads back
/// with inherited entries, and an exact compare would call that drift.
#[test]
fn an_admin_file_under_etc_with_inherited_aces_passes() {
    let e = installed();
    let s = service_sid(WIN_SERVICE);
    let inherited = format!(
        "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;{s})"
    );
    e.plant(DROP_IN, &inherited);
    e.set_sddl(CONFIG_FILE, &inherited);
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());
}

#[test]
fn a_users_writable_or_other_owner_file_under_etc_fails() {
    let s = service_sid(WIN_SERVICE);
    for bad in [
        // Users may write, inherited or not.
        "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;BU)".to_string(),
        "O:BAG:SYD:(A;;FW;;;BU)".to_string(),
        // Any other owner holds WRITE_DAC whatever the DACL says.
        format!("O:{USER}G:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"),
        // The service may not write here.
        format!("O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;{s})"),
        format!("O:{s}G:SYD:AI(A;ID;FA;;;SY)"),
        // New children would get this.
        "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;OICIIO;FA;;;BU)".to_string(),
    ] {
        let e = installed();
        e.plant(DROP_IN, &bad);
        let c = e.doctor();
        let c = get(&c, "files.acl");
        assert_eq!(c.status, Status::Fail, "{bad}");
        assert!(c.detail.contains("10-admin.toml"), "{}", c.detail);
    }
}

/// Only below `etc`: `etc` itself is where those entries come from.
#[test]
fn the_etc_dir_itself_stays_exact() {
    let e = installed();
    e.set_sddl(
        r"C:\ProgramData\saiife\etc",
        "O:BAG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)",
    );
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);
}

/// A file the service made reads back as its own, inherited: spec §5.3a.3.
#[test]
fn a_file_the_service_made_passes_and_a_writable_one_does_not() {
    let s = service_sid(WIN_SERVICE);
    let e = installed();
    e.plant(
        STATE_DB,
        &format!("O:{s}G:{s}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{s})"),
    );
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());

    e.plant(
        STATE_DB,
        &format!("O:{s}G:{s}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{s})(A;ID;FR;;;BU)"),
    );
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);

    e.plant(STATE_DB, &user_owned());
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);
}

/// `<S>` writes only where its row says, and never the vault key.
#[test]
fn the_service_may_not_write_the_vault_key() {
    let s = service_sid(WIN_SERVICE);
    let e = installed();
    e.set_sddl(
        KEY,
        &format!("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{s})"),
    );
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Fail);
    assert_eq!(get(&r, "vault.key").status, Status::Fail);
}

#[test]
fn an_unfit_ancestor_fails() {
    for logical in [r"C:\", r"C:\ProgramData", r"C:\Program Files"] {
        let e = installed();
        e.set_sddl(logical, "O:BAG:SYD:P(A;;FA;;;BU)");
        let c = e.doctor();
        let c = get(&c, "files.acl");
        assert_eq!(c.status, Status::Fail, "{logical}");
        assert!(c.detail.contains(logical), "{logical}: {}", c.detail);
    }
}

#[test]
fn a_link_anywhere_in_the_tree_fails() {
    let e = installed();
    let outside = e.layout.root().join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, e.at(r"C:\ProgramData\saiife\state\planted")).unwrap();
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("reparse point"), "{}", c.detail);
}

/// A file the table has no row for still answers who may write it.
#[test]
fn a_file_with_no_row_must_still_be_protected() {
    let e = installed();
    e.plant(
        r"C:\ProgramData\saiife\bin\planted.dll",
        "O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)",
    );
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Pass);
    e.plant(r"C:\ProgramData\saiife\bin\planted.dll", &user_owned());
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);
}

/// Install holds this while doctor runs, and nobody else may open it.
#[test]
fn the_install_lock_is_not_read() {
    let e = installed();
    fs::write(e.at(WIN_INSTALL_LOCK), b"").unwrap();
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());
}

#[test]
fn a_missing_audit_group_fails_and_hides_nothing_else() {
    let e = installed();
    e.host.set(|s| {
        s.sids.remove(WIN_AUDIT_GROUP);
    });
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains(WIN_AUDIT_GROUP), "{}", c.detail);

    e.set_sddl(EXE, &user_owned());
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert!(c.detail.contains(EXE), "{}", c.detail);
}

#[test]
fn an_audit_group_of_well_known_sid_fails() {
    let e = installed();
    e.host.set(|s| {
        s.sids
            .insert(WIN_AUDIT_GROUP.to_string(), "S-1-1-0".to_string());
    });
    let c = e.doctor();
    assert_eq!(get(&c, "files.acl").status, Status::Fail);
}

// ----------------------------------------------------------------- dirs of other products

/// Ruling on W14: an agent's own leaf dir must pass `protected_ok`, so a stock
/// inherited one, where Users may create entries, fails: a user could plant settings.
/// Install refuses such a dir, so here it is loosened after a clean install.
#[test]
fn a_leaf_dir_users_can_add_to_fails() {
    let e = stock_machine(PeFixture::default());
    e.install(&Agent::ALL);
    let leaf = e.at(GEMINI);
    assert!(leaf.is_dir());
    e.host.set(|s| {
        s.sddl.insert(leaf.clone(), stock::PROGRAM_DATA.to_string());
        s.daemon_status = Some(answer());
    });
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains(GEMINI), "{}", c.detail);
}

/// `C:\ProgramData\OpenAI` belongs to another product and only needs `ancestor_ok`. A
/// user-owned one still fails.
#[test]
fn a_foreign_parent_needs_only_ancestor_ok() {
    let openai = r"C:\ProgramData\OpenAI";
    let e = stock_machine(PeFixture::default());
    let p = e.at(openai);
    fs::create_dir_all(&p).unwrap();
    e.host.set(|s| {
        s.sddl.insert(p.clone(), stock::PROGRAM_DATA.to_string());
    });
    e.install(&Agent::ALL);
    e.host.set(|s| {
        s.daemon_status = Some(answer());
        s.authenticode = Some(0);
    });
    e.audit_key_as_the_daemon_left_it();
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());

    e.set_sddl(openai, &user_owned());
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Fail);
}

/// An agent not listed has no paths doctor relies on.
#[test]
fn an_agent_not_listed_is_not_looked_at() {
    let e = stock_machine(PeFixture::default());
    e.install(&[Agent::Claude]);
    e.host.set(|s| s.daemon_status = Some(answer()));
    e.audit_key_as_the_daemon_left_it();
    let leaf = e.at(GEMINI);
    fs::create_dir_all(&leaf).unwrap();
    e.host.set(|s| {
        s.sddl.insert(leaf.clone(), user_owned());
    });
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());
}

// ----------------------------------------------------------------- the service

#[test]
fn service_sddl_drift_fails_daemon_unit() {
    let e = installed();
    e.edit_live(|s| s.sddl.push_str("(A;;RPWP;;;BU)"));
    let r = e.doctor();
    let c = get(&r, "daemon.unit");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("descriptor"), "{}", c.detail);
}

/// The recorded fingerprint is right in all of these, so only the live compare sees them.
#[test]
fn live_service_drift_fails_daemon_unit() {
    type Edit = fn(&mut crate::winservice::ServiceSpec);
    let cases: Vec<(&str, Edit)> = vec![
        ("binary", |s| {
            s.binary = PathBuf::from(r"C:\Users\a\evil.exe")
        }),
        ("arguments", |s| s.args = vec!["daemon".into()]),
        ("account", |s| s.account = "LocalSystem".into()),
        ("start", |s| s.start = StartKind::Manual),
        ("start", |s| s.start = StartKind::Disabled),
        ("SID type", |s| s.sid_type = SidType::None),
        ("failure", |s| s.failure.restarts = 0),
        ("failure", |s| s.failure.on_non_crash = false),
        ("display", |s| s.display = "other".into()),
        ("descriptor", |s| s.sddl = "not sddl".into()),
        ("descriptor", |s| {
            // Users may stop it: every ACE but one as W10 says.
            s.sddl = s
                .sddl
                .replace("(A;;CCLCSWLORC;;;AU)", "(A;;CCLCSWRPWPLORC;;;AU)")
        }),
    ];
    for (word, edit) in cases {
        let e = installed();
        e.edit_live(edit);
        let r = e.doctor();
        let c = get(&r, "daemon.unit");
        assert_eq!(c.status, Status::Fail, "{word}");
        assert!(c.detail.contains(word), "{word}: {}", c.detail);
    }
}

/// `sc.exe sdshow` prints the service's SACL too, and spellings Windows chooses. It is the
/// DACL that W10 fixes, compared parsed.
#[test]
fn the_live_descriptor_compares_parsed_and_without_its_sacl() {
    let e = installed();
    e.edit_live(|s| {
        s.sddl = format!(
            "\r\n{}S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)\r\n",
            WIN_SERVICE_SDDL.replace("IU", "S-1-5-4")
        )
    });
    let r = e.doctor();
    assert_eq!(
        get(&r, "daemon.unit").status,
        Status::Pass,
        "{}",
        r.to_text()
    );
}

/// Windows keeps names as they were given and ignores their case.
#[test]
fn the_live_compare_ignores_case_where_windows_does() {
    let e = installed();
    e.edit_live(|s| {
        s.binary = PathBuf::from(s.binary.to_string_lossy().to_uppercase());
        s.account = s.account.to_lowercase();
    });
    assert_eq!(get(&e.doctor(), "daemon.unit").status, Status::Pass);
}

#[test]
fn a_recorded_fingerprint_that_differs_fails() {
    let e = installed();
    let at = e.at(r"C:\ProgramData\saiife\etc\installed.toml");
    let mut rec = read_installed(&at).unwrap().unwrap();
    for f in &mut rec.files {
        if f.kind == saiife_policy::installed::FileKind::Service {
            f.sha256 = Some("0".repeat(64));
        }
    }
    write_installed(&at, &rec).unwrap();
    let c = e.doctor();
    let c = get(&c, "daemon.unit");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("fingerprint"), "{}", c.detail);
}

#[test]
fn a_service_that_is_stopped_missing_or_unreadable_fails() {
    let e = installed();
    e.host.set(|s| s.service_running = false);
    assert_eq!(get(&e.doctor(), "daemon.unit").status, Status::Fail);

    let e = installed();
    e.host.set(|s| s.service_spec_error = Some("nope".into()));
    assert_eq!(get(&e.doctor(), "daemon.unit").status, Status::Fail);

    let e = installed();
    e.host.set(|s| {
        s.services.clear();
    });
    let c = e.doctor();
    let c = get(&c, "daemon.unit");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("does not exist"), "{}", c.detail);
}

#[test]
fn a_service_a_plain_shell_may_not_read_is_not_checked() {
    let e = installed();
    e.host.set(|s| {
        s.euid = 1000;
        s.service_spec_denied = true;
    });
    let r = e.doctor();
    let c = get(&r, "daemon.unit");
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("not checked"), "{}", c.detail);
    assert_ne!(r.exit_code(), 0);

    let e = installed();
    e.host.set(|s| s.service_spec_denied = true);
    assert_eq!(get(&e.doctor(), "daemon.unit").status, Status::Fail);
}

/// No record, and the service manager will not say whether there is a service.
#[test]
fn a_service_manager_that_cannot_be_asked_is_no_developer_mode() {
    let e = stock_machine(PeFixture::default());
    e.host.set(|s| s.service_query_error = Some("no".into()));
    let c = e.doctor();
    let c = get(&c, "install.record");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains("could not"), "{}", c.detail);

    let e = installed();
    e.host.set(|s| s.service_query_error = Some("no".into()));
    assert_eq!(get(&e.doctor(), "daemon.unit").status, Status::Fail);
}

/// What the real host builds from the service manager's answers.
#[test]
fn the_live_spec_reads_back_as_w10() {
    use crate::winservice::{failure_policy_from, live_spec_from, sdshow_text, LiveService};
    use std::time::Duration as D;
    let want = ServiceSpec::saiifed(&Layout::system_for(Platform::Windows));
    let restart = (true, D::from_secs(1));
    let live = |command: &str, failure| {
        live_spec_from(LiveService {
            display: "saiife daemon".to_string(),
            command_line: command.to_string(),
            account: r"NT Service\saiifed".to_string(),
            start: StartKind::Auto,
            sid_type: SidType::Unrestricted,
            failure,
            sddl: format!("\r\n{WIN_SERVICE_SDDL}\r\n"),
        })
    };
    let good = failure_policy_from(&[restart; 3], D::from_secs(86_400), true);
    for command in [
        r"C:\ProgramData\saiife\bin\saiife.exe daemon --system",
        r#""C:\ProgramData\saiife\bin\saiife.exe" daemon --system"#,
    ] {
        let d = service_drift(&want, &live(command, good.clone()));
        assert!(d.is_empty(), "{command}: {d:?}");
    }
    let command = r"C:\ProgramData\saiife\bin\saiife.exe daemon --system";
    for (word, actions, reset, non_crash) in [
        ("two restarts", vec![restart; 2], 86_400, true),
        ("no actions", vec![], 86_400, true),
        (
            "a mix",
            vec![restart, (false, D::from_secs(1)), restart],
            86_400,
            true,
        ),
        (
            "uneven delays",
            vec![restart, restart, (true, D::from_secs(9))],
            86_400,
            true,
        ),
        ("never resets", vec![restart; 3], 0, true),
        ("not on a clean exit", vec![restart; 3], 86_400, false),
    ] {
        let f = failure_policy_from(&actions, D::from_secs(reset), non_crash);
        let d = service_drift(&want, &live(command, f));
        assert!(d.iter().any(|x| x.contains("failure")), "{word}: {d:?}");
    }

    assert_eq!(
        sdshow_text(0, "\r\nD:(A;;RC;;;SY)\r\n").unwrap(),
        "D:(A;;RC;;;SY)"
    );
    assert!(sdshow_text(0, " \r\n").is_err());
    assert_eq!(
        sdshow_text(5, "").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_ne!(
        sdshow_text(1060, "").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn authenticode_codes_read_as_they_mean() {
    use crate::binary::{authenticode_verdict as v, Authenticode as A};
    assert_eq!(v(0), A::Valid);
    assert!(matches!(v(0x800B_0100u32 as i32), A::Rejected(_)));
    assert!(matches!(v(1), A::Rejected(_)));
    assert!(matches!(v(0x8007_0002u32 as i32), A::Unknown(_)));
    assert!(matches!(v(0x800B_0003u32 as i32), A::Unknown(_)));
}

/// What `system install` does with the report: the failure, then what `--package` makes of
/// it, on a Windows layout.
#[test]
fn after_install_reports_logs_and_exits_as_the_package_needs() {
    use crate::install::{package_exit, write_package_log, InstallReport};
    let e = installed();
    let opts = DoctorOptions::default();
    let dir = FixedDirectory::from_text(SYSTEM_CONFIG_USERS, "");
    let (text, failed) = crate::doctor::after_install(&e.layout, &e.host, &dir, &opts);
    assert!(!failed, "{text}");

    e.host.set(|s| s.daemon_status = None);
    let (text, failed) = crate::doctor::after_install(&e.layout, &e.host, &dir, &opts);
    assert!(failed);
    assert!(text.contains("FAIL  daemon.health"), "{text}");
    let exit = InstallReport::default().exit_code(failed);
    assert_eq!(exit, 1);
    assert_eq!(package_exit(exit, false), 1);
    assert_eq!(package_exit(exit, true), 0);
    write_package_log(&e.layout, &e.host, &text).unwrap();
    let log = fs::read_to_string(e.at(WIN_INSTALL_LOG)).unwrap();
    assert!(log.contains("FAIL  daemon.health"), "{log}");
}

/// package-windows, CI run 9: the doctor after `msiexec /i` exited 2 where install's own
/// doctor, run before the log existed, did not. The log has no row and its dir passes on no
/// entries, so only the descriptor install gives it keeps doctor's walk clean.
#[test]
fn the_install_log_keeps_files_acl_clean() {
    use crate::install::write_package_log;
    let e = installed();
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Pass);
    write_package_log(&e.layout, &e.host, "doctor text\n").unwrap();
    let report = e.doctor();
    let after = get(&report, "files.acl");
    assert_eq!(after.status, Status::Pass, "{}", after.detail);
    write_package_log(&e.layout, &e.host, "again\n").unwrap();
    assert_eq!(get(&e.doctor(), "files.acl").status, Status::Pass);
}

#[test]
fn a_daemon_with_no_policy_fails_health() {
    let e = installed();
    e.host.set(|s| {
        let mut a = answer();
        a.insert("policy_ok".into(), json!(false));
        s.daemon_status = Some(a);
    });
    assert_eq!(get(&e.doctor(), "daemon.health").status, Status::Fail);
}

// ----------------------------------------------------------------- the binary

fn swap_binary(e: &Env, pe: PeFixture) {
    fs::write(e.at(EXE), pe_fixture(pe)).unwrap();
}

/// A release doctor fails a test build; a test-build doctor (the `ci-locked` binary that
/// `locked-windows` installs with `--allow-test-build`) warns, as on Linux and macOS. Other
/// problems fail either way.
#[test]
fn a_test_build_fails_under_a_release_doctor_and_warns_under_a_test_one() {
    let info = |pe| crate::binary::inspect_pe(&pe_fixture(pe)).unwrap();
    let debug = info(PeFixture {
        marker: Some(true),
        ..PeFixture::default()
    });
    let (problems, notes) = pe_findings(&debug, false);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("test build"), "{problems:?}");
    assert!(notes.is_empty(), "{notes:?}");
    let (problems, notes) = pe_findings(&debug, true);
    assert!(problems.is_empty(), "{problems:?}");
    assert!(notes[0].starts_with("test build installed"), "{notes:?}");

    let both = info(PeFixture {
        marker: Some(true),
        flags: 0,
        signed: false,
        ..PeFixture::default()
    });
    let (problems, notes) = pe_findings(&both, true);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("DependentLoadFlags"), "{problems:?}");
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(notes[1].contains("Authenticode"), "{notes:?}");

    let release = info(PeFixture::default());
    assert_eq!(pe_findings(&release, true), pe_findings(&release, false));
    assert_eq!(pe_findings(&release, false), (Vec::new(), Vec::new()));
    let unknown = info(PeFixture {
        marker: None,
        ..PeFixture::default()
    });
    assert!(!pe_findings(&unknown, true).0.is_empty());
}

#[test]
fn a_debug_or_unhardened_binary_fails() {
    let e = installed();
    swap_binary(
        &e,
        PeFixture {
            marker: Some(true),
            ..PeFixture::default()
        },
    );
    let r = e.doctor();
    let c = get(&r, "files.binary");
    if cfg!(debug_assertions) {
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains("test build installed"), "{}", c.detail);
    } else {
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
    }
    for pe in [
        PeFixture {
            flags: 0,
            ..PeFixture::default()
        },
        PeFixture {
            imports: vec!["evil.dll"],
            ..PeFixture::default()
        },
    ] {
        let e = installed();
        swap_binary(&e, pe);
        assert_eq!(get(&e.doctor(), "files.binary").status, Status::Fail);
    }
    let e = installed();
    fs::write(e.at(EXE), b"not a pe").unwrap();
    assert_eq!(get(&e.doctor(), "files.binary").status, Status::Fail);
    fs::remove_file(e.at(EXE)).unwrap();
    assert_eq!(get(&e.doctor(), "files.binary").status, Status::Fail);
}

#[test]
fn an_unsigned_binary_warns_and_powershell_is_not_asked() {
    let e = installed();
    swap_binary(
        &e,
        PeFixture {
            signed: false,
            ..PeFixture::default()
        },
    );
    e.host.set(|s| s.calls.clear());
    let r = e.doctor();
    let c = get(&r, "files.binary");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains("Authenticode"), "{}", c.detail);
    assert!(!e
        .host
        .state()
        .calls
        .iter()
        .any(|l| l.starts_with("authenticode")));
}

#[test]
fn a_signature_windows_rejects_fails() {
    for (code, word) in [
        (0x800B_0100u32, "TRUST_E_NOSIGNATURE"),
        (0x8009_6010, "TRUST_E_BAD_DIGEST"),
        (0x800B_0109, "CERT_E_UNTRUSTEDROOT"),
        (0x800B_0999, "0x800B0999"),
    ] {
        let e = installed();
        e.host.set(|s| s.authenticode = Some(code as i32));
        let c = e.doctor();
        let c = get(&c, "files.binary");
        assert_eq!(c.status, Status::Fail, "{word}");
        assert!(c.detail.contains(word), "{}", c.detail);
    }
}

/// The signature was not seen to be good, so this is not a pass, and not seen to be bad.
#[test]
fn a_signature_that_cannot_be_read_warns() {
    for code in [
        None,
        Some(0x8007_0005u32 as i32),
        Some(0x800B_0001u32 as i32),
    ] {
        let e = installed();
        e.host.set(|s| s.authenticode = code);
        let c = e.doctor();
        let c = get(&c, "files.binary");
        assert_eq!(c.status, Status::Warn, "{code:?}");
        assert!(c.detail.contains("could not"), "{}", c.detail);
    }
}

/// An elevated doctor starts no program to read a signature: the caller's user controls what
/// such a program finds in its environment and in HKCU, and it would run with the full token.
#[test]
fn the_signature_is_read_in_process_and_no_program_runs() {
    let e = installed();
    e.host.set(|s| s.calls.clear());
    let r = e.doctor();
    assert_eq!(get(&r, "files.binary").status, Status::Pass);
    let calls = e.host.state().calls;
    let asked = format!("authenticode {}", e.at(EXE).display());
    assert!(calls.contains(&asked), "{calls:?}");
    for c in &calls {
        assert!(
            !c.to_ascii_lowercase().contains("powershell"),
            "{c}: {calls:?}"
        );
        assert!(!c.starts_with(r"C:\"), "an elevated doctor ran {c}");
    }
}

#[test]
fn a_child_gets_a_fixed_environment_and_no_powershell_is_on_the_list() {
    use crate::host::{WINDOWS_CHILD_DIR, WINDOWS_CHILD_ENV, WIN_PROGRAMS};
    let names: Vec<&str> = WINDOWS_CHILD_ENV.iter().map(|(n, _)| *n).collect();
    for needed in ["SystemRoot", "Path"] {
        assert!(names.contains(&needed), "{names:?}");
    }
    for (name, value) in WINDOWS_CHILD_ENV {
        let upper = name.to_ascii_uppercase();
        assert!(
            !upper.starts_with("PS") && !upper.starts_with("COR") && !upper.starts_with("__"),
            "{name}"
        );
        assert!(!value.contains('%'), "{name}={value}");
    }
    assert_eq!(WINDOWS_CHILD_DIR, r"C:\Windows\System32");
    assert!(!WIN_PROGRAMS
        .iter()
        .any(|p| p.to_ascii_lowercase().contains("powershell")));
}

#[test]
fn a_changed_file_fails_files_installed() {
    let e = installed();
    fs::write(e.at(CLAUDE_SETTINGS), b"{}").unwrap();
    let r = e.doctor();
    let c = get(&r, "files.installed");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("changed since install"), "{}", c.detail);

    // saiife's entry in a file it shares.
    let e = installed();
    fs::write(e.at(r"C:\ProgramData\gemini-cli\settings.json"), b"{}").unwrap();
    assert_eq!(get(&e.doctor(), "files.installed").status, Status::Fail);
}

/// The MSI's copy, in a folder as Windows leaves it.
fn package_copy(e: &Env) -> PathBuf {
    let copy = e.at(windows_path(PACKAGE_BINARY).unwrap());
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    fs::copy(e.at(EXE), &copy).unwrap();
    let inherited = "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";
    e.set_sddl(PACKAGE_DIR, inherited);
    e.set_sddl(windows_path(PACKAGE_BINARY).unwrap(), inherited);
    copy
}

const PACKAGE_DIR: &str = r"C:\Program Files\saiife";

#[test]
fn a_package_copy_that_differs_warns() {
    let e = installed();
    let copy = package_copy(&e);
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Pass);

    fs::write(&copy, b"older").unwrap();
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Warn);

    fs::copy(e.at(EXE), &copy).unwrap();
    e.set_sddl(windows_path(PACKAGE_BINARY).unwrap(), &user_owned());
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Warn);
}

/// SYSTEM runs this copy, and whoever may write the folder may swap it, as on Linux.
#[test]
fn a_package_folder_others_can_write_warns() {
    let e = installed();
    package_copy(&e);
    let drifted = format!("{}(A;;FW;;;BU)", e.sddl(PACKAGE_DIR));
    e.set_sddl(PACKAGE_DIR, &drifted);
    let c = e.doctor();
    let c = get(&c, "files.package");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains(PACKAGE_DIR), "{}", c.detail);

    let e = installed();
    package_copy(&e);
    e.set_sddl(r"C:\Program Files", "O:BAG:SYD:P(A;;FA;;;BU)");
    let c = e.doctor();
    let c = get(&c, "files.package");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains(r"C:\Program Files"), "{}", c.detail);
}

/// Only a copy that is not there drops the check. Not being able to look is no absence.
#[test]
fn a_package_copy_doctor_cannot_look_at_is_said() {
    use std::os::unix::fs::PermissionsExt;
    let e = installed();
    package_copy(&e);
    let dir = e.at(PACKAGE_DIR);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
    let r = e.doctor();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        get(&r, "files.package").status,
        Status::Warn,
        "{}",
        r.to_text()
    );
    assert!(!installed()
        .doctor()
        .checks
        .iter()
        .any(|c| c.id == "files.package"));
}

// ----------------------------------------------------------------- the audit key

#[test]
fn the_audit_key_is_checked() {
    let e = installed();
    assert_eq!(get(&e.doctor(), "keys").status, Status::Pass);

    fs::write(e.at(AUDIT_KEY_FILE), b"short").unwrap();
    let c = e.doctor();
    let c = get(&c, "keys");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("32 bytes"), "{}", c.detail);

    fs::remove_file(e.at(AUDIT_KEY_FILE)).unwrap();
    let r = e.doctor();
    assert_eq!(get(&r, "keys").status, Status::Fail);
    assert_eq!(get(&r, "files.acl").status, Status::Fail);
}

// ----------------------------------------------------------------- the vault key

#[test]
fn a_vault_key_on_record_with_another_mode_fails() {
    let e = installed();
    let at = e.at(r"C:\ProgramData\saiife\etc\installed.toml");
    let mut rec = read_installed(&at).unwrap().unwrap();
    rec.vault_key = saiife_policy::installed::VaultKeyMode::Credential;
    write_installed(&at, &rec).unwrap();
    assert_eq!(get(&e.doctor(), "vault.key").status, Status::Fail);
}

#[test]
fn a_vault_key_of_the_wrong_length_fails() {
    let e = installed();
    fs::write(e.at(KEY), b"short").unwrap();
    assert_eq!(get(&e.doctor(), "vault.key").status, Status::Fail);
}

// ----------------------------------------------------------------- the Claude policy

fn hklm(e: &Env, text: &str) {
    e.host.set(|s| {
        s.registry.insert(
            (
                saiife_agents::claude::HKLM_POLICY_KEY.to_string(),
                saiife_agents::claude::HKLM_POLICY_VALUE.to_string(),
            ),
            RegValue::Str(text.to_string()),
        );
    });
}

#[test]
fn hklm_overrides_fails_claude_policy() {
    let e = installed();
    assert_eq!(
        get(&e.doctor(), "agents.claude.policy").status,
        Status::Pass
    );

    hklm(&e, r#"{"permissions":{"deny":[]}}"#);
    let r = e.doctor();
    let c = get(&r, "agents.claude.policy");
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.detail, saiife_agents::claude::HKLM_OVERRIDES_TEXT);

    hklm(&e, r#"{"managedSourcesBehavior":"merge","permissions":{}}"#);
    assert_eq!(
        get(&e.doctor(), "agents.claude.policy").status,
        Status::Pass
    );
}

/// `merge` is no pass by itself: what it merges can still turn the hooks off.
#[test]
fn a_merged_policy_that_can_turn_hooks_off_fails() {
    let ours = saiife_agents::claude::managed_settings_for(true);
    let ours: serde_json::Value = serde_json::from_str(&ours).unwrap();
    let pattern = saiife_agents::claude::COSIGN_URL_PATTERN;
    let keeps = json!({"managedSourcesBehavior": "merge", "hooks": ours["hooks"],
        "allowedHttpHookUrls": [pattern]})
    .to_string();
    // The commands kept, the co-signer's HTTP handler dropped (plan 20).
    let mut commands = ours["hooks"].clone();
    commands["PreToolUse"][0]["hooks"]
        .as_array_mut()
        .unwrap()
        .retain(|h| h["type"] == "command");
    let commands_only = json!({"managedSourcesBehavior": "merge", "hooks": commands,
        "allowedHttpHookUrls": [pattern]})
    .to_string();
    for (settings, status) in [
        (commands_only.as_str(), Status::Fail),
        (
            r#"{"managedSourcesBehavior":"merge","disableAllHooks":true}"#,
            Status::Fail,
        ),
        // Whatever else it may mean, it does not say false.
        (
            r#"{"managedSourcesBehavior":"merge","disableAllHooks":"true"}"#,
            Status::Fail,
        ),
        (
            r#"{"managedSourcesBehavior":"merge","disableAllHooks":false}"#,
            Status::Pass,
        ),
        (
            r#"{"managedSourcesBehavior":"merge","hooks":{}}"#,
            Status::Fail,
        ),
        (
            r#"{"managedSourcesBehavior":"merge","hooks":null}"#,
            Status::Fail,
        ),
        (
            r#"{"managedSourcesBehavior":"merge","hooks":{"PreToolUse":[]}}"#,
            Status::Fail,
        ),
        (keeps.as_str(), Status::Pass),
    ] {
        let e = installed();
        hklm(&e, settings);
        let r = e.doctor();
        let c = get(&r, "agents.claude.policy");
        assert_eq!(c.status, status, "{settings}");
        if status == Status::Fail {
            assert_eq!(c.detail, saiife_agents::claude::HKLM_WEAKENS_HOOKS_TEXT);
        }
    }
}

/// W24's read fails closed, and doctor must too.
#[test]
fn an_unreadable_hklm_value_fails_claude_policy() {
    let e = installed();
    e.host.set(|s| {
        s.registry.insert(
            (
                saiife_agents::claude::HKLM_POLICY_KEY.to_string(),
                saiife_agents::claude::HKLM_POLICY_VALUE.to_string(),
            ),
            RegValue::Other,
        );
    });
    assert_eq!(
        get(&e.doctor(), "agents.claude.policy").status,
        Status::Fail
    );
}

#[test]
fn claude_policy_is_only_for_claude() {
    let e = stock_machine(PeFixture::default());
    e.install(&[Agent::Gemini]);
    hklm(&e, r#"{"permissions":{}}"#);
    let r = e.doctor();
    assert!(!r.checks.iter().any(|c| c.id == "agents.claude.policy"));
    assert!(!r.checks.iter().any(|c| c.id == "mcp.claude.allowlist"));
}

/// A drop-in from before the co-signer fails `agents.claude.policy`, whatever HKLM says.
#[test]
fn drop_in_without_cosign_fails_policy() {
    let e = installed();
    assert_eq!(
        get(&e.doctor(), "agents.claude.policy").status,
        Status::Pass
    );
    let old = saiife_agents::claude::managed_settings_for(true)
        .replace(
            ",\n                   { \"type\": \"http\",\n                     \"url\": \"http://127.0.0.1:7433/v1/cosign/claude\",\n                     \"timeout\": 10, \"onFailure\": \"block\" }",
            "",
        )
        .replace("  \"allowedHttpHookUrls\": [\"http://127.0.0.1:7433/*\"],\n", "");
    assert!(!old.contains("http://"), "{old}");
    fs::write(e.at(CLAUDE_SETTINGS), &old).unwrap();
    let r = e.doctor();
    let c = get(&r, "agents.claude.policy");
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.detail, saiife_agents::claude::COSIGN_MISSING_TEXT);

    hklm(&e, r#"{"managedSourcesBehavior":"merge","permissions":{}}"#);
    assert_eq!(
        get(&e.doctor(), "agents.claude.policy").status,
        Status::Fail
    );
}

// ----------------------------------------------------------------- the MCP drop-in

/// Task 6 owes this: `claude_pin_ok` is the hook's, and doctor checks the owner and ACL.
#[test]
fn a_user_writable_mcp_drop_in_fails_with_its_owner_and_acl() {
    let e = installed();
    assert_eq!(
        get(&e.doctor(), "mcp.claude.allowlist").status,
        Status::Pass
    );
    for bad in [user_owned(), format!("{}(A;;FW;;;BU)", e.sddl(MCP))] {
        e.set_sddl(MCP, &bad);
        let r = e.doctor();
        assert_eq!(
            get(&r, "mcp.claude.allowlist").status,
            Status::Fail,
            "{bad}"
        );
        assert_eq!(get(&r, "files.acl").status, Status::Fail, "{bad}");
    }
}

#[test]
fn an_mcp_drop_in_that_differs_warns_and_a_missing_one_fails_acl() {
    let e = installed();
    fs::write(e.at(MCP), b"{}").unwrap();
    assert_eq!(
        get(&e.doctor(), "mcp.claude.allowlist").status,
        Status::Warn
    );

    fs::remove_file(e.at(MCP)).unwrap();
    let r = e.doctor();
    assert_ne!(get(&r, "mcp.claude.allowlist").status, Status::Pass);
    assert_eq!(get(&r, "files.acl").status, Status::Fail);
}

// ----------------------------------------------------------------- W27

#[test]
fn admin_agent_user_fails_by_default() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Administrators", ADMINISTRATORS)]);
    // The stock machine: consent, no password.
    e.uac(5, 1, 1);
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.root");
    assert_eq!(c.status, Status::Fail, "{}", r.to_text());
    assert!(c.detail.contains("administrator"), "{}", c.detail);
}

#[test]
fn admin_agent_user_warns_with_credential_prompt() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Administrators", ADMINISTRATORS)]);
    e.uac(1, 1, 1);
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.root");
    assert_eq!(c.status, Status::Warn, "{}", r.to_text());
    assert_eq!(
        c.detail,
        "agent user alice is an administrator: elevation needs its password"
    );
}

/// Each half of the policy is needed, and neither can be assumed when it cannot be read.
#[test]
fn only_the_whole_credential_policy_softens_an_admin() {
    for (consent, secure, lua) in [
        (5, 1, 1),
        (1, 0, 1),
        (2, 1, 1),
        (0, 1, 1),
        // UAC off: the user's every process already holds full rights.
        (1, 1, 0),
    ] {
        let e = installed();
        e.user_in(ALICE, USER, &[("Administrators", ADMINISTRATORS)]);
        e.uac(consent, secure, lua);
        let r = e.doctor_as(Some(ALICE));
        assert_eq!(
            get(&r, "user.alice.root").status,
            Status::Fail,
            "{consent} {secure} {lua}"
        );
    }
    // No values at all.
    let e = installed();
    e.user_in(ALICE, USER, &[("Administrators", ADMINISTRATORS)]);
    assert_eq!(
        get(&e.doctor_as(Some(ALICE)), "user.alice.root").status,
        Status::Fail
    );
}

/// The built-in Administrator runs elevated in every process by default, whatever the
/// consent policy asks of others.
#[test]
fn the_built_in_administrator_never_softens() {
    let e = installed();
    e.user_in(
        "Administrator",
        "S-1-5-21-9-9-9-500",
        &[("Administrators", ADMINISTRATORS)],
    );
    e.uac(1, 1, 1);
    let r = e.doctor_as(Some("Administrator"));
    assert_eq!(get(&r, "user.Administrator.root").status, Status::Fail);
}

#[test]
fn backup_operators_fails() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Backup Operators", "S-1-5-32-551")]);
    // Softens only `Administrators`.
    e.uac(1, 1, 1);
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.root");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("Backup Operators"), "{}", c.detail);
}

#[test]
fn every_root_equivalent_group_fails() {
    for (name, sid) in [
        ("Server Operators", "S-1-5-32-549"),
        ("Hyper-V Administrators", "S-1-5-32-578"),
        ("Account Operators", "S-1-5-32-548"),
    ] {
        let e = installed();
        e.user_in(ALICE, USER, &[(name, sid)]);
        e.uac(1, 1, 1);
        let c = e.doctor_as(Some(ALICE));
        assert_eq!(get(&c, "user.alice.root").status, Status::Fail, "{name}");
    }
}

/// Group names are localized: on a German machine `Administrators` is `Administratoren`,
/// and a compare by name would pass that user.
#[test]
fn a_localized_group_name_changes_nothing() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Administratoren", ADMINISTRATORS)]);
    e.uac(5, 1, 1);
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.root").status, Status::Fail);

    e.user_in(ALICE, USER, &[("Sicherungs-Operatoren", "S-1-5-32-551")]);
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.root").status, Status::Fail);
}

/// A name saying nothing: only the SID counts, the other way round too.
#[test]
fn a_group_named_like_administrators_with_another_sid_passes() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Administrators", "S-1-5-21-9-9-9-2000")]);
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.root").status, Status::Pass);
}

#[test]
fn a_plain_user_passes() {
    let e = installed();
    e.user_in(ALICE, USER, &[("Users", "S-1-5-32-545")]);
    assert_eq!(
        get(&e.doctor_as(Some(ALICE)), "user.alice.root").status,
        Status::Pass
    );
}

/// An unknown is never a pass.
#[test]
fn groups_that_cannot_be_read_or_resolved_fail() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| s.local_groups_error = Some("no".into()));
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.root").status, Status::Fail);

    let e = installed();
    e.user_in(ALICE, USER, &[("Users", "S-1-5-32-545")]);
    e.host.set(|s| {
        s.sids.remove("Users");
    });
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.root").status, Status::Fail);
}

#[test]
fn an_unknown_user_fails() {
    let r = installed().doctor_as(Some("nobody"));
    let c = get(&r, "user.nobody.passwd");
    assert_eq!(c.status, Status::Fail);
}

#[test]
fn scoped_users_are_checked_and_groups_expanded() {
    let e = installed();
    fs::write(
        e.at(CONFIG_FILE),
        format!(
            "{}\n[[scope]]\nname = \"a\"\nusers = [\"alice\", \"group:devs\"]\n",
            fs::read_to_string(e.at(CONFIG_FILE)).unwrap()
        ),
    )
    .unwrap();
    e.user_in(ALICE, USER, &[("Administrators", ADMINISTRATORS)]);
    e.user_in("bob", "S-1-5-21-9-9-9-1002", &[("Users", "S-1-5-32-545")]);
    e.host.set(|s| {
        s.groups.insert("devs".to_string(), 77);
        s.members
            .insert("devs".to_string(), vec!["bob".to_string()]);
    });
    let dir = FixedDirectory::from_text(
        "alice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1000::/home/bob:/bin/sh\n",
        "devs:x:77:bob\n",
    );
    let r = run(&e.layout, &e.host, &dir, &DoctorOptions::default());
    assert_eq!(
        get(&r, "config.valid").status,
        Status::Pass,
        "{}",
        r.to_text()
    );
    assert_eq!(get(&r, "user.alice.root").status, Status::Fail);
    assert_eq!(get(&r, "user.bob.root").status, Status::Pass);
}

/// Who a group holds is unknown, so who is checked is too. The fake knows only the names
/// install makes as missing.
#[test]
fn a_scope_group_that_cannot_be_listed_fails() {
    let scoped = |group: &str| {
        let e = installed();
        fs::write(
            e.at(CONFIG_FILE),
            format!(
                "{}\n[[scope]]\nname = \"a\"\nusers = [\"group:{group}\"]\n",
                fs::read_to_string(e.at(CONFIG_FILE)).unwrap()
            ),
        )
        .unwrap();
        e
    };
    let dir = FixedDirectory::from_text("", "saiife:x:77:\ndevs:x:78:\n");
    let doctor = |e: &Env| run(&e.layout, &e.host, &dir, &DoctorOptions::default());

    let e = scoped("saiife");
    let r = doctor(&e);
    assert_eq!(
        get(&r, "scope.group.saiife").status,
        Status::Fail,
        "{}",
        r.to_text()
    );

    // A nested group or a deleted account: never a user name.
    let e = scoped("devs");
    e.host.set(|s| {
        s.groups.insert("devs".to_string(), 78);
        s.members.insert(
            "devs".to_string(),
            vec!["<member without a name>".to_string()],
        );
    });
    let r = doctor(&e);
    let c = get(&r, "scope.group.devs");
    assert_eq!(c.status, Status::Fail, "{}", r.to_text());
    assert!(c.detail.contains("without a name"), "{}", c.detail);
}

/// W27 went unevaluated, so an admin agent user would never fail: not fine, and not a fact.
#[test]
fn no_user_to_check_warns_and_names_w27() {
    let r = installed().doctor();
    let c = get(&r, "users.none");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains("W27"), "{}", c.detail);
    assert!(c.detail.contains("administrator"), "{}", c.detail);
}

/// A plain shell's denial of what a user's groups are is not a verdict on them.
#[test]
fn groups_a_plain_shell_may_not_read_warn() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| {
        s.euid = 1000;
        s.local_groups_denied = true;
    });
    let c = e.doctor_as(Some(ALICE));
    let c = get(&c, "user.alice.root");
    assert_eq!(c.status, Status::Warn);
    assert!(c.detail.contains("not checked"), "{}", c.detail);

    // Elevated there is no excuse.
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| s.local_groups_denied = true);
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.root").status, Status::Fail);
}

// ----------------------------------------------------------------- agent binaries

fn profile(e: &Env, sid: &str, value: &str) {
    e.host.set(|s| {
        s.registry.insert(
            (
                format!(r"{}\{sid}", crate::supported::REG_PROFILE_LIST),
                "ProfileImagePath".to_string(),
            ),
            RegValue::Str(value.to_string()),
        );
    });
}

#[test]
fn an_agent_binary_the_user_can_write_warns() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    profile(&e, USER, r"C:\Users\alice");
    let exe = r"C:\Users\alice\.local\bin\claude.exe";
    let npm = r"C:\Users\alice\AppData\Roaming\npm\codex.cmd";
    e.plant(exe, &format!("O:{USER}G:{USER}D:AI(A;ID;FA;;;{USER})"));
    e.plant(npm, &format!("O:{USER}G:{USER}D:AI(A;ID;FA;;;{USER})"));
    for dir in [
        r"C:\Users\alice\.local\bin",
        r"C:\Users\alice\AppData\Roaming\npm",
    ] {
        e.set_sddl(dir, &format!("O:{USER}G:{USER}D:AI(A;OICIID;FA;;;{USER})"));
    }
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.agent-binaries");
    assert_eq!(c.status, Status::Warn, "{}", r.to_text());
    assert!(c.detail.contains("claude.exe"), "{}", c.detail);
    assert!(c.detail.contains("codex.cmd"), "{}", c.detail);
}

#[test]
fn an_agent_binary_only_admins_can_write_passes() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    profile(&e, USER, r"%SystemDrive%\Users\alice");
    let exe = r"C:\Users\alice\.local\bin\claude.exe";
    let locked = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
    e.plant(exe, locked);
    e.set_sddl(r"C:\Users\alice\.local\bin", locked);
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.agent-binaries").status, Status::Pass);

    // Its folder counts: whoever may write there may swap the file.
    e.set_sddl(r"C:\Users\alice\.local\bin", &user_owned());
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.agent-binaries").status, Status::Warn);
}

#[test]
fn a_binary_doctor_cannot_judge_is_no_pass() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    profile(&e, USER, r"C:\Users\alice");
    let exe = e.at(r"C:\Users\alice\.local\bin\claude.exe");
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, b"x").unwrap();
    // No descriptor on record.
    let c = e.doctor_as(Some(ALICE));
    assert_eq!(get(&c, "user.alice.agent-binaries").status, Status::Warn);
}

#[test]
fn no_profile_and_no_binary_are_said() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    let c = e.doctor_as(Some(ALICE));
    let c = get(&c, "user.alice.agent-binaries");
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("profile"), "{}", c.detail);

    profile(&e, USER, r"C:\Users\alice");
    let c = e.doctor_as(Some(ALICE));
    let c = get(&c, "user.alice.agent-binaries");
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("no agent binary"), "{}", c.detail);

    // A value that does not plainly name a folder of this machine.
    for odd in [r"%HOMEDRIVE%\x", r"\\server\share\alice"] {
        profile(&e, USER, odd);
        let c = e.doctor_as(Some(ALICE));
        assert!(
            get(&c, "user.alice.agent-binaries")
                .detail
                .contains("profile"),
            "{odd}"
        );
    }
}

/// Each user's Linux lines that have no Windows form yet are said to be missing, so their
/// absence reads as "not checked" and not as "fine".
#[test]
fn checks_not_ported_are_named() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "host.not-ported");
    assert_eq!(c.status, Status::Info);
    for word in ["plaintext credentials", "hard links", "saiife-audit"] {
        assert!(c.detail.contains(word), "{word}: {}", c.detail);
    }
    assert_eq!(
        get(&r, "user.alice.egress").detail,
        "the egress recipe is Linux only"
    );
}

// ----------------------------------------------------------------- the service's spec

#[test]
fn the_service_compare_is_by_field() {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::under_for(dir.path(), Platform::Windows);
    let want = ServiceSpec::saiifed(&layout);
    assert!(service_drift(&want, &want).is_empty());
    let mut live = want.clone();
    live.start = StartKind::Manual;
    live.sid_type = SidType::Restricted;
    let drift = service_drift(&want, &live);
    assert_eq!(drift.len(), 2, "{drift:?}");
}

// ----------------------------------------------------------------- a moved audit dir

const MOVED: &str = r"C:\ProgramData\elsewhere\audit";

/// The config names the audit dir out of the tree, where no row covers it.
fn moved_audit(e: &Env) {
    let text = fs::read_to_string(e.at(CONFIG_FILE)).unwrap();
    let default = e
        .at(r"C:\ProgramData\saiife\log\audit")
        .display()
        .to_string();
    assert!(text.contains(&default), "{text}");
    let moved = e.at(MOVED);
    fs::write(
        e.at(CONFIG_FILE),
        text.replace(&default, &moved.display().to_string()),
    )
    .unwrap();
    fs::create_dir_all(&moved).unwrap();
    let locked = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    e.set_sddl(r"C:\ProgramData\elsewhere", locked);
    e.set_sddl(MOVED, locked);
}

#[test]
fn a_moved_audit_dir_must_hold_up_all_the_way() {
    let e = installed();
    moved_audit(&e);
    let r = e.doctor();
    assert_eq!(get(&r, "files.acl").status, Status::Pass, "{}", r.to_text());

    // What is in it.
    let month = r"C:\ProgramData\elsewhere\audit\2026\11.jsonl";
    e.plant(month, "O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)");
    e.set_sddl(
        r"C:\ProgramData\elsewhere\audit\2026",
        "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
    );
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains(month), "{}", c.detail);

    // The folder above it.
    let e = installed();
    moved_audit(&e);
    e.set_sddl(r"C:\ProgramData\elsewhere", &user_owned());
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(
        c.detail.contains(r"C:\ProgramData\elsewhere"),
        "{}",
        c.detail
    );

    // Not there at all.
    let e = installed();
    moved_audit(&e);
    fs::remove_dir(e.at(MOVED)).unwrap();
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("missing"), "{}", c.detail);

    // A link in it.
    let e = installed();
    moved_audit(&e);
    std::os::unix::fs::symlink(e.layout.root(), e.at(r"C:\ProgramData\elsewhere\audit\l")).unwrap();
    let c = e.doctor();
    let c = get(&c, "files.acl");
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("reparse point"), "{}", c.detail);
}

// ----------------------------------------------------------------- denied, not absent

#[test]
fn a_folder_of_binaries_doctor_may_not_read_is_no_absence() {
    use std::os::unix::fs::PermissionsExt;
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    profile(&e, USER, r"C:\Users\alice");
    let dir = e.at(r"C:\Users\alice\.local\bin");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
    let r = e.doctor_as(Some(ALICE));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let c = get(&r, "user.alice.agent-binaries");
    assert_eq!(c.status, Status::Warn, "{}", r.to_text());
    assert!(c.detail.contains("cannot look"), "{}", c.detail);
    assert!(!c.detail.contains("no agent binary"), "{}", c.detail);
}

// ----------------------------------------------------------------- agent versions

/// Alice's `claude.exe`, with doctor run from alice's own token unless a test says otherwise.
fn claude_exe(e: &Env, version: Option<(&str, i32)>) -> String {
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| s.own_sid = Some(USER.to_string()));
    profile(e, USER, r"C:\Users\alice");
    let exe = r"C:\Users\alice\.local\bin\claude.exe";
    let locked = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    e.plant(exe, locked);
    e.set_sddl(r"C:\Users\alice\.local\bin", locked);
    let line = format!("{} --version", e.at(exe).display());
    if let Some((out, status)) = version {
        e.host
            .set(|s| drop(s.run.insert(line.clone(), canned(out, status))));
    }
    line
}

#[test]
fn a_plain_shell_reads_the_agent_version() {
    let plain = |version: Option<(&str, i32)>| {
        let e = installed();
        claude_exe(&e, version);
        e.host.set(|s| s.euid = 1000);
        let r = e.doctor_as(Some(ALICE));
        get(&r, "user.alice.agent-version").clone()
    };
    let c = plain(Some(("2.1.300 (Claude Code)\n", 0)));
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.detail, "Claude Code 2.1.300");
    let c = plain(Some(("2.0.1\n", 0)));
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("older than"), "{}", c.detail);
    assert_eq!(plain(Some(("nonsense", 0))).status, Status::Warn);
    assert_eq!(plain(Some(("2.1.300", 1))).status, Status::Warn);
    // The fake's default: exit 1, no output.
    assert_eq!(plain(None).status, Status::Warn);
}

/// The agent's own binary, which its user may have changed, never runs with a full token.
#[test]
fn an_elevated_doctor_never_runs_an_agent() {
    let e = installed();
    let line = claude_exe(&e, Some(("2.1.300", 0)));
    e.host.set(|s| s.calls.clear());
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.agent-version");
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("elevated"), "{}", c.detail);
    let calls = e.host.state().calls;
    assert!(!calls.contains(&line), "{calls:?}");
    assert!(!calls.iter().any(|l| l.contains("--version")), "{calls:?}");

    // A limited token of an admin is a plain shell, and holds nothing to steal.
    let e = installed();
    let line = claude_exe(&e, Some(("2.1.300", 0)));
    e.host.set(|s| s.limited_token = true);
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.agent-version").status, Status::Pass);
    assert!(e.host.state().calls.contains(&line));
}

/// Audit-gaps item 7: only alice's own plain token runs alice's binary.
#[test]
fn the_agent_binary_runs_only_as_its_own_user() {
    let ran = |e: &Env, line: &str| e.host.state().calls.iter().any(|l| l == line);

    // Another user's plain shell: alice may have made the binary anything.
    let e = installed();
    let line = claude_exe(&e, Some(("2.1.300", 0)));
    e.host.set(|s| {
        s.euid = 1000;
        s.own_sid = Some("S-1-5-21-1-2-3-1002".to_string());
        s.calls.clear();
    });
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.agent-version");
    assert_eq!(c.status, Status::Info, "{}", r.to_text());
    assert!(c.detail.contains("its own user"), "{}", c.detail);
    assert!(!ran(&e, &line), "{:?}", e.host.state().calls);

    // A token that cannot be read counts as elevated.
    let e = installed();
    let line = claude_exe(&e, Some(("2.1.300", 0)));
    e.host.set(|s| {
        s.euid = 1000;
        s.own_sid = None;
        s.calls.clear();
    });
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.agent-version");
    assert_eq!(c.status, Status::Info, "{}", r.to_text());
    assert!(c.detail.contains("cannot be read"), "{}", c.detail);
    assert!(!ran(&e, &line), "{:?}", e.host.state().calls);

    // Alice herself, not elevated: it runs.
    let e = installed();
    let line = claude_exe(&e, Some(("2.1.300", 0)));
    e.host.set(|s| {
        s.euid = 1000;
        s.calls.clear();
    });
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.agent-version").status, Status::Pass);
    assert!(ran(&e, &line));
}

#[test]
fn no_binary_or_no_profile_reads_as_not_found() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    e.host.set(|s| s.euid = 1000);
    let r = e.doctor_as(Some(ALICE));
    assert_eq!(get(&r, "user.alice.agent-version").status, Status::Info);
    profile(&e, USER, r"C:\Users\alice");
    let r = e.doctor_as(Some(ALICE));
    let c = get(&r, "user.alice.agent-version");
    assert_eq!(c.status, Status::Info);
    assert!(c.detail.contains("not found"), "{}", c.detail);
}

// ----------------------------------------------------------------- plan 20

fn answer_with(cosign: serde_json::Value, n: u64) -> Map<String, serde_json::Value> {
    let mut a = answer();
    a.insert("cosign".into(), cosign);
    let last = (n > 0).then_some("2026-11-09T10:00:00Z");
    a.insert(
        "hooks_no_verdict".into(),
        json!({"since_start": n, "last_ts": last}),
    );
    a
}

#[test]
fn cosign_not_listening_fails() {
    let e = installed();
    let down = json!({"addr": null, "error": "only one usage of each socket address"});
    e.host.set(|s| s.daemon_status = Some(answer_with(down, 0)));
    let r = e.doctor();
    assert_eq!(get(&r, "daemon.health").status, Status::Pass);
    let c = get(&r, "cosign.listen");
    assert_eq!(c.status, Status::Fail);
    assert_eq!(
        c.detail,
        "the co-signer is not listening on 127.0.0.1:7433 (only one usage of each socket \
         address), so Claude Code blocks every call"
    );
    // No answer at all: daemon.health fails, and this says it could not look.
    e.host.set(|s| s.daemon_status = None);
    let r = e.doctor();
    assert_eq!(get(&r, "daemon.health").status, Status::Fail);
    assert_eq!(get(&r, "cosign.listen").status, Status::Info);
    assert_eq!(get(&r, "hooks.no-verdict").status, Status::Info);
}

#[test]
fn cosign_listening_passes() {
    let r = installed().doctor();
    let c = get(&r, "cosign.listen");
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.detail, "listening on 127.0.0.1:7433");
}

#[test]
fn cosign_info_without_claude() {
    let e = stock_machine(PeFixture::default());
    e.install(&[Agent::Codex]);
    let down = json!({"addr": null, "error": "x"});
    e.host.set(|s| s.daemon_status = Some(answer_with(down, 0)));
    assert_eq!(get(&e.doctor(), "cosign.listen").status, Status::Info);
}

#[test]
fn no_verdict_warns_with_count() {
    let e = installed();
    let up = json!({"addr": "127.0.0.1:7433", "error": null});
    e.host.set(|s| s.daemon_status = Some(answer_with(up, 2)));
    let c = get(&e.doctor(), "hooks.no-verdict").clone();
    assert_eq!(c.status, Status::Warn);
    assert_eq!(
        c.detail,
        "2 hook call(s) ended without a verdict since the daemon started (last \
         2026-11-09T10:00:00Z): a hook was killed, crashed or timed out; see saiife audit \
         --kind hook"
    );
}

#[test]
fn no_verdict_zero_passes() {
    assert_eq!(
        get(&installed().doctor(), "hooks.no-verdict").status,
        Status::Pass
    );
}

/// The machine environment sets a proxy; the agent user's settings `env` may exempt
/// 127.0.0.1 from it. Never this process's environment.
#[test]
fn proxy_without_no_proxy_warns() {
    let e = installed();
    e.user_in(ALICE, USER, &[]);
    profile(&e, USER, r"C:\Users\alice");
    assert_eq!(
        get(&e.doctor_as(Some(ALICE)), "user.alice.proxy").status,
        Status::Pass
    );
    e.host.set(|s| {
        s.registry.insert(
            (REG_MACHINE_ENV.to_string(), "HTTPS_PROXY".to_string()),
            RegValue::Str("http://proxy.test:3128".into()),
        );
        // The caller's own environment says nothing of the agent user.
        s.env.insert("NO_PROXY".into(), "127.0.0.1".into());
    });
    let c = get(&e.doctor_as(Some(ALICE)), "user.alice.proxy").clone();
    assert_eq!(c.status, Status::Warn, "{c:?}");
    assert!(c.detail.contains("(in the machine environment)"), "{c:?}");
    let settings = e.at(r"C:\Users\alice\.claude\settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"env":{"NO_PROXY":"127.0.0.0/8"}}"#).unwrap();
    assert_eq!(
        get(&e.doctor_as(Some(ALICE)), "user.alice.proxy").status,
        Status::Pass
    );
}
