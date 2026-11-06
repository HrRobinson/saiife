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

/// The line [`signature`] runs.
fn powershell_line() -> String {
    format!(
        "{POWERSHELL_EXE} -NoProfile -NonInteractive -Command \
         (Get-AuthenticodeSignature -LiteralPath {}).Status",
        windows_path(BINARY).unwrap()
    )
}

fn canned(stdout: &str, status: i32) -> crate::host::CmdOutput {
    crate::host::CmdOutput {
        status,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

fn answer() -> Map<String, serde_json::Value> {
    json!({"policy_ok": true, "chain": "ok", "head_seq": 7, "last_checkpoint_seq": 6})
        .as_object()
        .unwrap()
        .clone()
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
        s.run.insert(powershell_line(), canned("Valid\r\n", 0));
    });
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
        "vault.key",
        "reauth",
        "peer.pidfd",
        "agents.claude.policy",
        "mcp.landlock",
        "mcp.claude.allowlist",
        "disk.encryption",
        "locked.preview",
        "forwarding",
    ] {
        get(&r, id);
    }
    for id in ["paths.owner", "files.modes", "keys", "daemon.group"] {
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
    // Owner ruling: not W16's password text.
    says(
        "reauth",
        "same-user approval is off on Windows: approvals need a second account",
    );
}

/// What the lock does not do must be said, in a line that fails nothing.
#[test]
fn the_preview_limits_are_said_and_fail_nothing() {
    let c = installed().doctor();
    let c = get(&c, "locked.preview");
    assert_eq!(c.status, Status::Info);
    for word in [
        "preview",
        "forge a hook's exit",
        "block the hook",
        "redirect its path",
        "unverified",
        "Codex",
        "Gemini",
    ] {
        assert!(c.detail.contains(word), "{word}: {}", c.detail);
    }
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
        s.run.insert(powershell_line(), canned("Valid", 0));
    });
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

#[test]
fn a_debug_or_unhardened_binary_fails() {
    for pe in [
        PeFixture {
            marker: Some(true),
            ..PeFixture::default()
        },
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
        .any(|l| l.contains("Get-Authenticode")));
}

#[test]
fn a_signature_windows_rejects_fails() {
    for word in ["HashMismatch", "NotTrusted", "NotSigned", "UnknownError"] {
        let e = installed();
        e.host
            .set(|s| drop(s.run.insert(powershell_line(), canned(word, 0))));
        let c = e.doctor();
        let c = get(&c, "files.binary");
        assert_eq!(c.status, Status::Fail, "{word}");
        assert!(c.detail.contains(word), "{}", c.detail);
    }
}

/// The signature was not seen to be good, so this is not a pass, and not seen to be bad.
#[test]
fn a_signature_that_cannot_be_read_warns() {
    for out in [canned("", 0), canned("Valid", 1)] {
        let e = installed();
        e.host
            .set(|s| drop(s.run.insert(powershell_line(), out.clone())));
        let c = e.doctor();
        let c = get(&c, "files.binary");
        assert_eq!(c.status, Status::Warn, "{out:?}");
        assert!(c.detail.contains("could not"), "{}", c.detail);
    }
}

#[test]
fn powershell_is_asked_with_the_fixed_path_and_no_profile() {
    let e = installed();
    e.host.set(|s| s.calls.clear());
    let r = e.doctor();
    assert_eq!(get(&r, "files.binary").status, Status::Pass);
    assert!(e.host.state().calls.contains(&powershell_line()));
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

#[test]
fn a_package_copy_that_differs_warns() {
    let e = installed();
    let copy = e.at(windows_path(PACKAGE_BINARY).unwrap());
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    fs::copy(e.at(EXE), &copy).unwrap();
    e.host.set(|s| {
        s.sddl.insert(
            copy.clone(),
            "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)".to_string(),
        );
    });
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Pass);

    fs::write(&copy, b"older").unwrap();
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Warn);

    fs::copy(e.at(EXE), &copy).unwrap();
    e.host.set(|s| {
        s.sddl.insert(copy.clone(), user_owned());
    });
    assert_eq!(get(&e.doctor(), "files.package").status, Status::Warn);
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

#[test]
fn no_user_to_check_is_said_and_is_no_pass() {
    let r = installed().doctor();
    let c = get(&r, "users.none");
    assert_eq!(c.status, Status::Info);
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
    for word in [
        "plaintext credentials",
        "agent versions",
        "audit signing key",
    ] {
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
