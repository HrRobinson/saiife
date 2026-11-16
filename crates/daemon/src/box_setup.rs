//! The daemon's side of the guest channel of real boxes (plan 38, Task 8):
//! what a box's guest is set up with ([`TemplateSetup`]), the late-bound
//! gateway hook ([`LateHooks`]) and where a box's terminal recording goes
//! ([`cast_path`]).
//!
//! The setup is the box template's command, the agent's model env and files
//! (plan 40: the box's placeholder, never the real credential; for Claude
//! Code its first-run seed and settings (G11), for Codex and Gemini their
//! config with the gateway as provider, plan 42 D5) and the user packs of
//! this daemon's `policy.d/packs`, on a 40 x 120 terminal. A pack that
//! cannot be sent (an invalid id, too big, over the file count) is skipped
//! with one stderr line naming it: a spawn is never refused for a pack.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use saiife_boxes::guest::GuestEvent;
use saiife_boxes::manager::Manager;
use saiife_boxes::store::Store;
use saiife_boxes::template::{
    AgentKind, Login, ModelCred, SUBSCRIPTION_GATED, SUBSCRIPTION_LOGIN_CLEARED,
};
use saiife_boxes::BoxId;
use saiife_boxhost::guest::{
    claude_env, claude_json_seed, claude_settings, codex_config, codex_env, gemini_env,
    gemini_settings, pack_files, CastPath, SetupSource, VsockGuest,
};
use saiife_boxhost::paths::{BoxPaths, RecordPaths};
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
        // Plan 40 C4 beyond spawn: a template edited to subscription after
        // spawn sets up nothing (no OAuth placeholder is made) until the
        // owner's terms check flips the constant.
        if t.login == Login::Subscription && !SUBSCRIPTION_LOGIN_CLEARED {
            return Err(SUBSCRIPTION_GATED.into());
        }
        let record = RecordPaths::of(mgr.root(), id);
        drop(mgr);
        // Runs on the guest channel's own thread (never under the manager
        // lock or on an async runtime), so the file I/O may block. Every
        // fresh guest init asks again (plan 38 R22): the placeholder is
        // read back, so a re-setup carries the same env and approval.
        // A placeholder file of another agent's shape (the template was
        // switched after spawn) is refused, never remade (plan 42 D3).
        let p = read_or_make_placeholder(&record, t.model_cred())
            .map_err(|e| format!("the box's model placeholder: {e}"))?;
        let packs = user_packs(id, &self.packs);
        match t.agent {
            AgentKind::ClaudeCode => {
                let model = Some(ModelSetup {
                    env: claude_env(t.login, &p),
                    seed: claude_json_seed(&p),
                });
                build_setup(id, &t.command, model, &packs)
            }
            AgentKind::Codex | AgentKind::Gemini => build_agent_setup(
                id,
                &t.command,
                agent_setup(t.agent, t.model_cred(), &p),
                &packs,
            ),
        }
    }
}

/// Where the in-box Codex config goes (plan 42 D5).
pub const CODEX_CONFIG_PATH: &str = "/home/agent/.codex/config.toml";
/// Where the in-box Gemini CLI settings go (plan 42 D5).
pub const GEMINI_SETTINGS_PATH: &str = "/home/agent/.gemini/settings.json";

/// What an agent kind adds to a box's setup: its model env and its files.
pub struct AgentSetup {
    pub env: Vec<(String, String)>,
    pub files: Vec<SetupFile>,
}

/// A 0600 file saiife's setup rewrites on every setup (the agent's own
/// edits last until the next cold boot).
fn authoritative(path: &str, text: String) -> SetupFile {
    SetupFile {
        path: path.into(),
        mode: 0o600,
        text,
        keep_existing: false,
    }
}

/// Claude Code's part: the settings, plus the model env and once-only
/// `.claude.json` seed when given (plan 38 G11, plan 40 C2).
fn claude_setup(model: Option<ModelSetup>) -> AgentSetup {
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
    AgentSetup { env, files }
}

/// The env and files of `agent` with the box's `placeholder` (plan 42 D5).
/// `cred` picks Claude Code's login variable; Codex and Gemini have one
/// login each. Codex's hooks are not here: they are managed, baked into the
/// image (R7, `codex_requirements`). No agent gets another agent's files.
pub fn agent_setup(agent: AgentKind, cred: ModelCred, placeholder: &str) -> AgentSetup {
    match agent {
        AgentKind::ClaudeCode => {
            let login = match cred {
                ModelCred::AnthropicSubscription => Login::Subscription,
                _ => Login::ApiKey,
            };
            claude_setup(Some(ModelSetup {
                env: claude_env(login, placeholder),
                seed: claude_json_seed(placeholder),
            }))
        }
        AgentKind::Codex => AgentSetup {
            env: codex_env(placeholder),
            files: vec![authoritative(CODEX_CONFIG_PATH, codex_config())],
        },
        AgentKind::Gemini => AgentSetup {
            env: gemini_env(placeholder),
            files: vec![authoritative(GEMINI_SETTINGS_PATH, gemini_settings())],
        },
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

/// The setup of a Claude Code box `id`: [`build_agent_setup`] with the
/// Claude Code settings, and the model env and `.claude.json` seed when
/// given.
pub fn build_setup(
    id: &BoxId,
    command: &[String],
    model: Option<ModelSetup>,
    packs: &[(String, String)],
) -> Result<Setup, String> {
    build_agent_setup(id, command, claude_setup(model), packs)
}

/// The setup of box `id`: `command`, the agent's env and files (they count
/// against the env and file limits; only packs are skippable), then each
/// pack that fits (invalid id, a text over [`MAX_FILE_TEXT`], past
/// [`MAX_FILES`] files or past [`MAX_USER_PACK_BYTES`] of packs: skipped,
/// one line each). `Setup::check` runs last; its error is the answer.
pub fn build_agent_setup(
    id: &BoxId,
    command: &[String],
    agent: AgentSetup,
    packs: &[(String, String)],
) -> Result<Setup, String> {
    let AgentSetup { env, mut files } = agent;
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

    fn other_agents() -> [(AgentKind, ModelCred, &'static str); 2] {
        [
            (AgentKind::Codex, ModelCred::OpenAiApiKey, "codex"),
            (AgentKind::Gemini, ModelCred::GoogleApiKey, "gemini"),
        ]
    }

    fn one_pack() -> Vec<(String, String)> {
        vec![("user.one".to_string(), "a = 1".to_string())]
    }

    #[test]
    fn codex_box_has_no_claude_files() {
        let cmd = vec!["codex".to_string()];
        let a = agent_setup(AgentKind::Codex, ModelCred::OpenAiApiKey, "PH");
        let s = build_agent_setup(&b1(), &cmd, a, &one_pack()).unwrap();
        assert_eq!(s.agent.command, cmd);
        assert_eq!(s.env, codex_env("PH"));
        let paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                CODEX_CONFIG_PATH,
                "/home/agent/.config/saiife/packs/user.one.toml"
            ]
        );
        assert_eq!(s.files[0].text, codex_config());
        assert!(!paths.contains(&SETTINGS_PATH));
        assert!(!paths.contains(&CLAUDE_JSON_PATH));
        assert_eq!(CODEX_CONFIG_PATH, "/home/agent/.codex/config.toml");
    }

    #[test]
    fn gemini_box_has_no_claude_files() {
        let cmd = vec!["gemini".to_string()];
        let a = agent_setup(AgentKind::Gemini, ModelCred::GoogleApiKey, "PH");
        let s = build_agent_setup(&b1(), &cmd, a, &one_pack()).unwrap();
        assert_eq!(s.agent.command, cmd);
        assert_eq!(s.env, gemini_env("PH"));
        let paths: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                GEMINI_SETTINGS_PATH,
                "/home/agent/.config/saiife/packs/user.one.toml"
            ]
        );
        assert_eq!(s.files[0].text, gemini_settings());
        assert!(!paths.contains(&SETTINGS_PATH));
        assert!(!paths.contains(&CLAUDE_JSON_PATH));
        assert_eq!(GEMINI_SETTINGS_PATH, "/home/agent/.gemini/settings.json");
    }

    #[test]
    fn agent_files_are_0600_and_authoritative() {
        for (agent, cred, _) in other_agents() {
            let a = agent_setup(agent, cred, "PH");
            assert_eq!(a.files.len(), 1, "{agent:?}");
            for f in &a.files {
                assert_eq!((f.mode, f.keep_existing), (0o600, false), "{}", f.path);
                assert!(!f.text.contains("PH"), "no placeholder in {}", f.path);
            }
        }
    }

    /// R7: Codex runs without a hook-trust bypass and with no user-level
    /// hooks: saiife's are managed, in the image.
    #[test]
    fn codex_setup_has_no_hook_bypass() {
        let a = agent_setup(AgentKind::Codex, ModelCred::OpenAiApiKey, "PH");
        for f in &a.files {
            assert!(
                !f.text.contains("--dangerously-bypass-hook-trust"),
                "{}",
                f.path
            );
            let v: toml::Table = toml::from_str(&f.text).unwrap();
            assert!(!v.contains_key("hooks"), "{}", f.path);
            assert!(!f.text.contains("[[hooks"), "{}", f.path);
        }
        for (k, v) in &a.env {
            assert!(!v.contains("--dangerously-bypass-hook-trust"), "{k}");
            assert!(!v.contains("hooks"), "{k}");
        }
        let builtin = saiife_boxes::template::builtin();
        let codex = builtin
            .iter()
            .find(|t| t.agent == AgentKind::Codex)
            .unwrap();
        assert!(!codex
            .command
            .iter()
            .any(|c| c.contains("--dangerously-bypass-hook-trust")));
    }

    /// Plan 38/40 behaviour through the new builder: a Claude Code box's
    /// agent setup is the settings and the once-only seed.
    #[test]
    fn claude_agent_setup_is_settings_and_seed() {
        let a = agent_setup(AgentKind::ClaudeCode, ModelCred::AnthropicApiKey, "PH");
        assert_eq!(a.env, claude_env(Login::ApiKey, "PH"));
        let paths: Vec<&str> = a.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec![SETTINGS_PATH, CLAUDE_JSON_PATH]);
        let a = agent_setup(
            AgentKind::ClaudeCode,
            ModelCred::AnthropicSubscription,
            "PH",
        );
        assert_eq!(a.env, claude_env(Login::Subscription, "PH"));
    }

    #[cfg(feature = "fake-vmm")]
    mod with_manager {
        use super::*;
        use saiife_boxes::capacity::{self, HostFacts};
        use saiife_boxes::guest::fake::FakeGuest;
        use saiife_boxes::guest::GuestLink;
        use saiife_boxes::manager::{ManagerInit, SpawnArgs};
        use saiife_boxes::template::{BoxTemplate, Size};
        use saiife_boxes::vmm::fake::FakeVmm;
        use saiife_boxhost::placeholder::OTHER_AGENT;

        fn tmpl(name: &str, agent: AgentKind) -> BoxTemplate {
            let mut t = saiife_boxes::template::builtin()
                .into_iter()
                .find(|t| t.agent == agent)
                .unwrap();
            t.name = name.into();
            t
        }

        fn manager(state: &Path, templates: Vec<BoxTemplate>) -> Arc<Manager> {
            let host = HostFacts {
                mem_total_mib: 8192 + 3 * capacity::charge_mib(&Size::default()),
                mem_avail_mib: 4096,
                threads: 12,
                disk_free_mib: 1024 * 1024,
                cpu_pct: None,
            };
            let guest: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
            Arc::new(
                Manager::open(ManagerInit {
                    store: Store::open(crate::box_ops::dir_in(state)).unwrap(),
                    vmm: Arc::new(FakeVmm::new()),
                    guest,
                    templates,
                    host: Arc::new(move || host),
                    clock: Arc::new(|| 1_000_000),
                    disk_place: crate::box_ops::disk_place(),
                })
                .unwrap()
                .manager,
            )
        }

        fn spawn(m: &Manager, template: &str) -> BoxId {
            m.spawn(&SpawnArgs {
                template: template.into(),
                repo: "shop".into(),
                repo_dir: None,
                task: String::new(),
                start: saiife_wire::source::Start::Queue,
                owner_uid: 2000,
                repo_image: None,
                base_manifest: None,
            })
            .unwrap()
            .id
        }

        fn setups(t: &tempfile::TempDir, m: &Arc<Manager>) -> Arc<TemplateSetup> {
            let s = TemplateSetup::new(t.path().join("packs"));
            s.attach(m);
            s
        }

        fn env_of(s: &Setup, k: &str) -> Option<String> {
            s.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        }

        /// The setup never holds a vault value: a secret stored under each
        /// route's service is absent from the serialized setup of a codex
        /// and a gemini box (only the placeholder travels).
        #[test]
        fn setup_has_no_secret_for_every_agent() {
            let t = scratch();
            let state = t.path().join("state");
            std::fs::create_dir_all(&state).unwrap();
            let key_file = t.path().join("vault-key");
            std::fs::write(&key_file, [7u8; 32]).unwrap();
            std::fs::set_permissions(
                &key_file,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .unwrap();
            let mut vault = crate::vault::open(&key_file, &state.join("vault").join("vault.bin"));
            let crate::vault::VaultState::Ready(v) = &mut vault else {
                panic!("vault not ready");
            };
            let secret = concat!("REAL", "SECRET", "-", "0123456789abcdef");
            for (name, service) in [
                ("openai", "box-model-openai"),
                ("gemini", "box-model-google"),
                ("anthropic", "box-model-anthropic"),
            ] {
                v.put(crate::vault::Entry {
                    name: name.into(),
                    kind: crate::vault::Kind::Token,
                    fields: [(
                        "token".to_string(),
                        zeroize::Zeroizing::new(secret.to_string()),
                    )]
                    .into(),
                    allowed_services: vec![service.into()],
                    created_by: 0,
                    created: "2026-11-16T00:00:00Z".into(),
                    last_used: None,
                    rotate_after: None,
                })
                .unwrap();
            }
            let m = manager(
                &state,
                vec![tmpl("cx", AgentKind::Codex), tmpl("gm", AgentKind::Gemini)],
            );
            let (c, g) = (spawn(&m, "cx"), spawn(&m, "gm"));
            let s = setups(&t, &m);
            for (b, var) in [(c, "OPENAI_API_KEY"), (g, "GEMINI_API_KEY")] {
                let json = serde_json::to_string(&s.setup_for(&b).unwrap()).unwrap();
                assert!(json.contains(var), "the setup is real");
                assert!(!json.contains(secret));
                assert!(!json.contains("REALSECRET"));
            }
        }

        /// A second setup of one box carries the same env and placeholder,
        /// per agent; another box of the same agent differs.
        #[test]
        fn second_setup_same_placeholder_per_agent() {
            let t = scratch();
            let m = manager(
                &t.path().join("state"),
                vec![tmpl("cx", AgentKind::Codex), tmpl("gm", AgentKind::Gemini)],
            );
            let s = setups(&t, &m);
            for (template, var, prefix) in [
                ("cx", "OPENAI_API_KEY", "saiife-openai-"),
                ("gm", "GEMINI_API_KEY", "saiife-google-"),
            ] {
                let b = spawn(&m, template);
                let s1 = s.setup_for(&b).unwrap();
                let s2 = s.setup_for(&b).unwrap();
                assert_eq!(s1, s2);
                let ph = env_of(&s1, var).unwrap();
                assert!(ph.starts_with(prefix), "{ph}");
                let rec = saiife_boxhost::layout::record_dir(m.root(), &b);
                assert_eq!(
                    std::fs::read_to_string(rec.join("placeholder")).unwrap(),
                    format!("{ph}\n")
                );
                let other = spawn(&m, template);
                assert_ne!(env_of(&s.setup_for(&other).unwrap(), var).unwrap(), ph);
            }
        }

        /// A box spawned as codex whose template now names gemini sets up
        /// nothing: the placeholder is another agent's, never remade.
        #[test]
        fn switched_agent_setup_is_refused() {
            let t = scratch();
            let state = t.path().join("state");
            let first = manager(&state, vec![tmpl("t", AgentKind::Codex)]);
            let b = spawn(&first, "t");
            setups(&t, &first).setup_for(&b).unwrap();
            let file = saiife_boxhost::paths::RecordPaths::of(first.root(), &b).placeholder();
            let before = std::fs::read(&file).unwrap();
            drop(first);
            let m = manager(&state, vec![tmpl("t", AgentKind::Gemini)]);
            let e = setups(&t, &m).setup_for(&b).unwrap_err();
            assert!(e.contains(OTHER_AGENT), "{e}");
            assert_eq!(std::fs::read(&file).unwrap(), before);
        }
    }
}
