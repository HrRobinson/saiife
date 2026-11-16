//! The daemon's side of the guest channel of real boxes (plan 38, Task 8):
//! what a box's guest is set up with ([`TemplateSetup`]), the late-bound
//! gateway hook ([`LateHooks`]) and where a box's terminal recording goes
//! ([`cast_path`]).
//!
//! The setup is the box template's command, the model env and first-run
//! seed of Claude Code (plan 40: the box's placeholder, never the real
//! credential), the in-box Claude Code settings (G11) and the user packs of
//! this daemon's `policy.d/packs`, on a 40 x 120 terminal. A pack that
//! cannot be sent (an invalid id, too big, over the file count) is skipped
//! with one stderr line naming it: a spawn is never refused for a pack.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use saiife_boxes::guest::GuestEvent;
use saiife_boxes::manager::Manager;
use saiife_boxes::store::Store;
use saiife_boxes::template::AgentKind;
use saiife_boxes::BoxId;
use saiife_boxhost::guest::{
    claude_env, claude_json_seed, claude_settings, pack_files, CastPath, SetupSource, VsockGuest,
};
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::placeholder::read_or_make_placeholder;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::msg::{AgentSpec, Setup, SetupFile, MAX_FILES, MAX_FILE_TEXT};
use saiife_policy::userpacks::{read_user_packs, MAX_USER_PACK_BYTES, USER_PACKS_DIR};

use crate::box_ops::GuestEvents;

/// Where the in-box Claude Code settings go (G11).
pub const SETTINGS_PATH: &str = "/home/agent/.claude/settings.json";
/// Claude Code's own state file, seeded once (never overwritten: it is sent
/// with `keep_existing`).
pub const CLAUDE_JSON_PATH: &str = "/home/agent/.claude.json";
/// The agent's terminal (G4).
pub const ROWS: u16 = 40;
pub const COLS: u16 = 120;
/// What a boot answers before the gateway hook is filled.
pub const GATEWAY_NOT_READY: &str = "the box gateway is not ready";
/// What a setup answers before the manager is attached.
pub const MANAGER_NOT_READY: &str = "the box manager is not ready";

/// `<dir of config_path>/policy.d/packs`: the user packs this daemon loads
/// (plan 32).
pub fn packs_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("/"))
        .join("policy.d")
        .join(USER_PACKS_DIR)
}

fn log(id: &BoxId, msg: &str) {
    eprintln!(
        "saiifed: boxes: {}: {}",
        id.as_str(),
        saiife_audit::text::sanitize(msg)
    );
}

/// The [`SetupSource`] of real boxes: the box's template from the manager
/// (attached once it exists: the manager holds the guest channel that
/// holds this), the user packs read fresh at each setup.
pub struct TemplateSetup {
    mgr: OnceLock<Weak<Manager>>,
    packs: PathBuf,
}

impl TemplateSetup {
    pub fn new(packs_dir: PathBuf) -> Arc<TemplateSetup> {
        Arc::new(TemplateSetup {
            mgr: OnceLock::new(),
            packs: packs_dir,
        })
    }

    /// The manager whose records name each box's template. Once.
    pub fn attach(&self, mgr: &Arc<Manager>) {
        let _ = self.mgr.set(Arc::downgrade(mgr));
    }
}

impl SetupSource for TemplateSetup {
    fn setup_for(&self, id: &BoxId) -> Result<Setup, String> {
        let mgr = self
            .mgr
            .get()
            .and_then(Weak::upgrade)
            .ok_or(MANAGER_NOT_READY)?;
        let r = mgr.get(id).map_err(|e| e.to_string())?;
        let t = mgr
            .templates()
            .into_iter()
            .find(|t| t.name == r.template)
            .ok_or_else(|| format!("the template {:?} is gone", r.template))?;
        let record = saiife_boxhost::layout::record_dir(mgr.root(), id);
        drop(mgr);
        // Runs on the guest channel's own thread (never under the manager
        // lock or on an async runtime), so the file I/O may block. Every
        // fresh guest init asks again (plan 38 R22): the placeholder is
        // read back, so a re-setup carries the same env and approval.
        let model = match t.agent {
            AgentKind::ClaudeCode => {
                let p = read_or_make_placeholder(&record, t.login)
                    .map_err(|e| format!("the box's model placeholder: {e}"))?;
                Some(ModelSetup {
                    env: claude_env(t.login, &p),
                    seed: claude_json_seed(&p),
                })
            }
        };
        build_setup(id, &t.command, model, &user_packs(id, &self.packs))
    }
}

/// What the model path adds to a Claude Code box's setup.
pub struct ModelSetup {
    pub env: Vec<(String, String)>,
    pub seed: String,
}

/// The user packs as `(id, text)`; a dir that cannot be read sends none
/// (one line saying why).
fn user_packs(id: &BoxId, dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    match read_user_packs(dir, &mut files) {
        Ok(packs) => packs.into_iter().map(|p| (p.id, p.text)).collect(),
        Err(e) => {
            log(id, &format!("no user packs sent: {e}"));
            Vec::new()
        }
    }
}

/// The setup of box `id`: `command`, the model env and `.claude.json` seed
/// when given (they count against the env and file limits; only packs are
/// skippable), the Claude Code settings, then each pack that fits (invalid
/// id, a text over [`MAX_FILE_TEXT`], past [`MAX_FILES`] files or past
/// [`MAX_USER_PACK_BYTES`] of packs: skipped, one line each). `Setup::check` runs last; its error is the answer.
pub fn build_setup(
    id: &BoxId,
    command: &[String],
    model: Option<ModelSetup>,
    packs: &[(String, String)],
) -> Result<Setup, String> {
    let mut files = vec![SetupFile {
        path: SETTINGS_PATH.into(),
        mode: 0o644,
        text: claude_settings(),
        keep_existing: false,
    }];
    let mut env = Vec::new();
    if let Some(m) = model {
        env = m.env;
        files.push(SetupFile {
            path: CLAUDE_JSON_PATH.into(),
            mode: 0o600,
            text: m.seed,
            keep_existing: true,
        });
    }
    let mut pack_bytes = 0usize;
    for (pid, text) in packs {
        let skip = |why: &str| log(id, &format!("user pack {pid:?} skipped: {why}"));
        if text.len() > MAX_FILE_TEXT {
            skip("more than 256 KiB");
            continue;
        }
        if files.len() >= MAX_FILES {
            skip("more than 64 setup files");
            continue;
        }
        if pack_bytes.saturating_add(text.len()) > MAX_USER_PACK_BYTES {
            skip("the packs total more than 256 KiB");
            continue;
        }
        match pack_files(&[(pid.clone(), text.clone())]) {
            Ok(f) => {
                pack_bytes += text.len();
                files.extend(f);
            }
            Err(e) => skip(&e),
        }
    }
    let setup = Setup {
        agent: AgentSpec {
            command: command.to_vec(),
            user: "agent".into(),
            cwd: "/work".into(),
        },
        env,
        files,
        rows: ROWS,
        cols: COLS,
    };
    setup.check()?;
    Ok(setup)
}

/// Where box `id`'s terminal recording goes (R15, R37): `term.cast` in its
/// record dir in the daemon's own state (`layout::record_dir` of the
/// store's root, where spawn also places the base manifest), never in the
/// VMM-writable runtime dir the guest channel is handed.
pub fn cast_path(store: Store) -> CastPath {
    Arc::new(move |id: &BoxId, _runtime: &BoxPaths| {
        saiife_boxhost::layout::record_dir(store.root(), id).join(saiife_boxhost::paths::TERM_CAST)
    })
}

/// A hook filled after the VMM exists: the gateway needs the daemon
/// context, which holds the manager, which holds the VMM, which holds its
/// hooks. Until [`LateHooks::fill`] every boot fails ([`GATEWAY_NOT_READY`]),
/// so no box runs without egress control.
#[derive(Default)]
pub struct LateHooks {
    slot: OnceLock<Arc<dyn VmHooks>>,
}

impl LateHooks {
    pub fn new() -> Arc<LateHooks> {
        Arc::new(LateHooks::default())
    }

    /// `false` when it was filled already (the first hook stays).
    pub fn fill(&self, h: Arc<dyn VmHooks>) -> bool {
        self.slot.set(h).is_ok()
    }
}

impl VmHooks for LateHooks {
    fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        match self.slot.get() {
            Some(h) => h.before_boot(id, paths),
            None => Err(GATEWAY_NOT_READY.into()),
        }
    }

    fn after_off(&self, id: &BoxId) {
        if let Some(h) = self.slot.get() {
            h.after_off(id);
        }
    }

    fn restore_refused(&self, id: &BoxId, why: &str) {
        if let Some(h) = self.slot.get() {
            h.restore_refused(id, why);
        }
    }
}

impl GuestEvents for VsockGuest {
    fn recv_events(&self, timeout: Duration) -> Vec<(BoxId, GuestEvent)> {
        VsockGuest::recv_events(self, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn b1() -> BoxId {
        BoxId::parse("b1").unwrap()
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir_in(
            std::env::var_os("SAIIFE_TEST_TMP")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
        .unwrap()
    }

    fn cmd() -> Vec<String> {
        vec!["claude".into()]
    }

    #[test]
    fn setup_is_settings_then_packs() {
        let packs = vec![(
            "user.one".to_string(),
            "[pack]\nid = \"user.one\"\n".to_string(),
        )];
        let s = build_setup(&b1(), &cmd(), None, &packs).unwrap();
        assert_eq!(s.agent.command, cmd());
        assert_eq!(s.agent.user, "agent");
        assert_eq!(s.agent.cwd, "/work");
        assert!(s.env.is_empty());
        assert_eq!((s.rows, s.cols), (40, 120));
        assert_eq!(s.files.len(), 2);
        assert_eq!(s.files[0].path, SETTINGS_PATH);
        assert_eq!(s.files[0].mode, 0o644);
        assert_eq!(s.files[0].text, claude_settings());
        assert_eq!(
            s.files[1].path,
            "/home/agent/.config/saiife/packs/user.one.toml"
        );
        assert_eq!(s.files[1].text, packs[0].1);
    }

    fn model() -> ModelSetup {
        ModelSetup {
            env: vec![("ANTHROPIC_API_KEY".into(), "PH".into())],
            seed: "{}".into(),
        }
    }

    /// The seed is sent once-only (keep_existing), 0600; the env travels.
    #[test]
    fn model_env_and_seed_are_in_the_setup() {
        let s = build_setup(&b1(), &cmd(), Some(model()), &[]).unwrap();
        assert_eq!(s.env, model().env);
        let paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec![SETTINGS_PATH, CLAUDE_JSON_PATH]);
        let seed = &s.files[1];
        assert_eq!((seed.mode, seed.keep_existing), (0o600, true));
        assert!(!s.files[0].keep_existing);
        assert_eq!(s.files[0].text, claude_settings());
    }

    /// The seed counts against the file limit; packs are what gives way.
    #[test]
    fn the_seed_survives_a_pack_flood() {
        let packs: Vec<(String, String)> = (0..100)
            .map(|i| (format!("user.p{i}"), "x".to_string()))
            .collect();
        let s = build_setup(&b1(), &cmd(), Some(model()), &packs).unwrap();
        assert_eq!(s.files.len(), MAX_FILES);
        assert!(s.files.iter().any(|f| f.path == CLAUDE_JSON_PATH));
        assert!(s.files.iter().any(|f| f.path == SETTINGS_PATH));
        assert!(s.check().is_ok());
    }

    #[test]
    fn bad_packs_are_skipped_not_refused() {
        let big = "x".repeat(MAX_FILE_TEXT + 1);
        let packs = vec![
            ("../evil".to_string(), "a".to_string()),
            ("user.big".to_string(), big),
            ("user.ok".to_string(), "b".to_string()),
        ];
        let s = build_setup(&b1(), &cmd(), None, &packs).unwrap();
        let paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                SETTINGS_PATH,
                "/home/agent/.config/saiife/packs/user.ok.toml"
            ]
        );
    }

    #[test]
    fn packs_stop_at_the_file_limit() {
        let packs: Vec<(String, String)> = (0..100)
            .map(|i| (format!("user.p{i}"), "x".to_string()))
            .collect();
        let s = build_setup(&b1(), &cmd(), None, &packs).unwrap();
        assert_eq!(s.files.len(), MAX_FILES);
        assert!(s.check().is_ok());
    }

    #[test]
    fn packs_stop_at_the_byte_budget() {
        let half = "x".repeat(MAX_USER_PACK_BYTES / 2 + 1);
        let packs = vec![
            ("user.a".to_string(), half.clone()),
            ("user.b".to_string(), half),
            ("user.c".to_string(), "small".to_string()),
        ];
        let s = build_setup(&b1(), &cmd(), None, &packs).unwrap();
        let names: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            names,
            vec![
                SETTINGS_PATH,
                "/home/agent/.config/saiife/packs/user.a.toml",
                "/home/agent/.config/saiife/packs/user.c.toml"
            ]
        );
    }

    #[test]
    fn an_invalid_setup_is_the_error() {
        let e = build_setup(&b1(), &[], None, &[]).unwrap_err();
        assert!(e.contains("agent command is empty"), "{e}");
    }

    #[test]
    fn setup_before_the_manager_is_refused() {
        let t = TemplateSetup::new(PathBuf::from("/nonexistent/p38/packs"));
        assert_eq!(t.setup_for(&b1()).unwrap_err(), MANAGER_NOT_READY);
    }

    #[test]
    fn packs_dir_is_beside_the_config() {
        assert_eq!(
            packs_dir(Path::new("/etc/saiife/config.toml")),
            Path::new("/etc/saiife/policy.d/packs")
        );
    }

    /// R15/R37: the recording is in the record dir, not the runtime dir.
    #[test]
    fn cast_path_is_in_the_records_dir() {
        let t = scratch();
        let records = crate::box_ops::dir_in(&t.path().join("state"));
        let runtime = t.path().join("state").join("box-run");
        let store = Store::open(records.clone()).unwrap();
        let want = store.box_dir(&b1()).join("term.cast");
        let p = cast_path(store)(&b1(), &BoxPaths::new(runtime.join("b1")));
        assert_eq!(p, want);
        assert_eq!(p, records.join("b1").join("term.cast"));
        assert!(!p.starts_with(&runtime));
        // the same record dir the spawn placer uses (R40)
        let place = saiife_boxhost::layout::record_disk_place(&records, &b1());
        assert_eq!(p.parent(), place.base_manifest.parent());
        assert_eq!(
            p,
            saiife_boxhost::layout::record_dir(&records, &b1())
                .join(saiife_boxhost::paths::TERM_CAST)
        );
    }

    #[derive(Default)]
    struct Spy(Mutex<Vec<String>>);
    impl VmHooks for Spy {
        fn before_boot(&self, id: &BoxId, _p: &BoxPaths) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("boot {}", id.as_str()));
            Ok(())
        }
        fn after_off(&self, id: &BoxId) {
            self.0.lock().unwrap().push(format!("off {}", id.as_str()));
        }
        fn restore_refused(&self, id: &BoxId, why: &str) {
            self.0
                .lock()
                .unwrap()
                .push(format!("refused {} {why}", id.as_str()));
        }
    }

    /// A boot before the gateway is filled fails closed; after, every call
    /// reaches the gateway.
    #[test]
    fn late_hooks_fail_closed_until_filled() {
        let late = LateHooks::new();
        let p = BoxPaths::new(PathBuf::from("/nonexistent/p38/b1"));
        assert_eq!(late.before_boot(&b1(), &p).unwrap_err(), GATEWAY_NOT_READY);
        late.after_off(&b1());
        let spy = Arc::new(Spy::default());
        assert!(late.fill(spy.clone()));
        assert!(!late.fill(Arc::new(Spy::default())), "filled once");
        late.before_boot(&b1(), &p).unwrap();
        late.restore_refused(&b1(), "bad");
        late.after_off(&b1());
        assert_eq!(
            *spy.0.lock().unwrap(),
            vec!["boot b1", "refused b1 bad", "off b1"]
        );
    }
}
