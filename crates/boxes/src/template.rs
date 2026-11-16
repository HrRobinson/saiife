//! Box templates (spec §7.8): the TOML format, loading from one trusted
//! directory, and the built-in `claude-code`.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use saiife_touch::TouchClass;
use serde::{Deserialize, Serialize};

/// The most vCPUs a template may give a box (also the VMM helper's hard
/// ceiling).
pub const MAX_VCPUS: u32 = 32;
/// The least memory a template may give a box, in MiB.
pub const MIN_MEM_MIB: u64 = 512;
/// The most memory a template may give a box, in MiB (also the VMM
/// helper's hard ceiling).
pub const MAX_MEM_MIB: u64 = 262_144;
/// Plan 40 C4: whether a template with `login = "subscription"` may spawn.
/// False until the owner has checked Anthropic's current terms for
/// subscription use through a local proxy (spec §7.9, §13). A one-line
/// change in its own commit, or subscription support is removed.
pub const SUBSCRIPTION_LOGIN_CLEARED: bool = false;
const BUILTIN_CLAUDE_CODE: &str = include_str!("builtin/claude-code.toml");
/// Largest template file read.
const MAX_FILE_BYTES: u64 = 64 * 1024;
/// The longest `[idle] stop_after_mins`: a week.
pub const MAX_IDLE_STOP_MINS: u32 = 7 * 24 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub vcpus: u32,
    pub mem_mib: u64,
    pub mem_max_mib: u64,
    pub disk_gib: u64,
}

impl Default for Size {
    fn default() -> Self {
        Size {
            vcpus: 2,
            mem_mib: 4096,
            mem_max_mib: 8192,
            disk_gib: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    ClaudeCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Login {
    ApiKey,
    Subscription,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRef {
    Default,
    Pinned(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoxTemplate {
    pub name: String,
    pub description: String,
    pub agent: AgentKind,
    pub command: Vec<String>,
    pub login: Login,
    pub credential: String,
    pub credential_in_box: bool,
    pub image: ImageRef,
    pub size: Size,
    pub egress: Vec<EgressRule>,
    pub secrets: Vec<String>,
    pub rules_profile: String,
    pub touch: Vec<TouchClass>,
    pub idle_stop_mins: u32,
}

impl BoxTemplate {
    /// How the model credential reaches the box, for `box ls` and the audit
    /// (plan 40 C3, R3): `"gateway"`, the host forwarder adds it, or
    /// `"in_box"`. Spawn refuses `credential_in_box`, so no box has the
    /// latter today; the one place the value is derived.
    pub fn credential_mode(&self) -> &'static str {
        if self.credential_in_box {
            "in_box"
        } else {
            "gateway"
        }
    }

    pub fn wire(&self) -> saiife_wire::source::Template {
        saiife_wire::source::Template {
            name: self.name.clone(),
            description: self.description.clone(),
            has_secrets: !self.secrets.is_empty(),
            has_egress: !self.egress.is_empty(),
            login: match self.login {
                Login::ApiKey => "api-key",
                Login::Subscription => "subscription",
            }
            .into(),
            credential_in_box: self.credential_in_box,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    name: String,
    description: String,
    agent: RawAgent,
    #[serde(default)]
    image: RawImage,
    #[serde(default)]
    size: RawSize,
    #[serde(default)]
    egress: RawEgress,
    #[serde(default)]
    secrets: RawSecrets,
    #[serde(default)]
    rules: RawRules,
    #[serde(default)]
    touch: RawTouch,
    #[serde(default)]
    idle: RawIdle,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    kind: String,
    command: Vec<String>,
    login: String,
    credential: String,
    #[serde(default)]
    credential_in_box: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    #[serde(default = "default_base")]
    base: String,
}
impl Default for RawImage {
    fn default() -> Self {
        RawImage {
            base: default_base(),
        }
    }
}
fn default_base() -> String {
    "default".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawSize {
    vcpus: u32,
    mem_mib: u64,
    mem_max_mib: u64,
    disk_gib: u64,
}
impl Default for RawSize {
    fn default() -> Self {
        let s = Size::default();
        RawSize {
            vcpus: s.vcpus,
            mem_mib: s.mem_mib,
            mem_max_mib: s.mem_max_mib,
            disk_gib: s.disk_gib,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawSecrets {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    #[serde(default = "default_profile")]
    profile: String,
}
impl Default for RawRules {
    fn default() -> Self {
        RawRules {
            profile: default_profile(),
        }
    }
}
fn default_profile() -> String {
    "default".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTouch {
    #[serde(default = "default_classes")]
    classes: Vec<String>,
}
impl Default for RawTouch {
    fn default() -> Self {
        RawTouch {
            classes: default_classes(),
        }
    }
}
fn default_classes() -> Vec<String> {
    vec!["land".into(), "push_protected".into()]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdle {
    #[serde(default = "default_idle")]
    stop_after_mins: u32,
}
impl Default for RawIdle {
    fn default() -> Self {
        RawIdle {
            stop_after_mins: default_idle(),
        }
    }
}
fn default_idle() -> u32 {
    120
}

/// `[a-z0-9][a-z0-9-]{0,39}`.
fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 40
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn parse_egress(s: &str) -> Result<EgressRule, String> {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| format!("egress {s:?}: bad port"))?;
            if port == 0 {
                return Err(format!("egress {s:?}: port 0"));
            }
            (h, port)
        }
        None => (s, 443),
    };
    let rest = host.strip_prefix("*.").unwrap_or(host);
    if rest.is_empty() || rest.len() > 253 {
        return Err(format!("egress {s:?}: bad host"));
    }
    for label in rest.split('.') {
        let b = label.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 63
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'));
        if !ok {
            return Err(format!("egress {s:?}: bad host"));
        }
    }
    Ok(EgressRule {
        host: host.to_string(),
        port,
    })
}

pub fn parse(name_from_stem: &str, text: &str) -> Result<BoxTemplate, String> {
    let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
    if !valid_name(&raw.name) {
        return Err(format!("bad template name {:?}", raw.name));
    }
    if raw.name != name_from_stem {
        return Err(format!(
            "name {:?} does not match file name {name_from_stem:?}",
            raw.name
        ));
    }
    if raw.description.len() > 200 || raw.description.chars().any(char::is_control) {
        return Err("bad description".into());
    }
    if raw.agent.kind != "claude-code" {
        return Err(format!("unknown agent kind {:?}", raw.agent.kind));
    }
    let login = match raw.agent.login.as_str() {
        "api-key" => Login::ApiKey,
        "subscription" => Login::Subscription,
        other => return Err(format!("unknown login {other:?}")),
    };
    if raw.agent.command.is_empty()
        || raw
            .agent
            .command
            .iter()
            .any(|c| c.is_empty() || c.contains('\0'))
    {
        return Err("command must be non-empty with non-empty elements and no NUL".into());
    }
    if !valid_name(&raw.agent.credential) {
        return Err(format!("bad credential name {:?}", raw.agent.credential));
    }
    let image = if raw.image.base == "default" {
        ImageRef::Default
    } else if let Some(hex) = raw.image.base.strip_prefix("base-") {
        if hex.len() == 64 && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            ImageRef::Pinned(raw.image.base.clone())
        } else {
            return Err("pinned image must be base-<64 lowercase hex>".into());
        }
    } else {
        return Err(format!("bad image base {:?}", raw.image.base));
    };
    let s = raw.size;
    if !(1..=MAX_VCPUS).contains(&s.vcpus) {
        return Err("vcpus must be 1..=32".into());
    }
    if !(MIN_MEM_MIB..=MAX_MEM_MIB).contains(&s.mem_mib) || s.mem_max_mib < s.mem_mib {
        return Err("memory: need 512 <= mem_mib <= 262144 and mem_max_mib >= mem_mib".into());
    }
    if !(10..=1024).contains(&s.disk_gib) {
        return Err("disk_gib must be 10..=1024".into());
    }
    let egress = raw
        .egress
        .allow
        .iter()
        .map(|e| parse_egress(e))
        .collect::<Result<Vec<_>, _>>()?;
    for n in &raw.secrets.names {
        if !valid_name(n) {
            return Err(format!("bad secret name {n:?}"));
        }
    }
    if !(1..=MAX_IDLE_STOP_MINS).contains(&raw.idle.stop_after_mins) {
        return Err(format!(
            "[idle] stop_after_mins must be 1..={MAX_IDLE_STOP_MINS}"
        ));
    }
    if !valid_name(&raw.rules.profile) {
        return Err(format!("bad rules profile {:?}", raw.rules.profile));
    }
    let touch = raw
        .touch
        .classes
        .iter()
        .map(|c| TouchClass::from_name(c).ok_or_else(|| format!("unknown touch class {c:?}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BoxTemplate {
        name: raw.name,
        description: raw.description,
        agent: AgentKind::ClaudeCode,
        command: raw.agent.command,
        login,
        credential: raw.agent.credential,
        credential_in_box: raw.agent.credential_in_box,
        image,
        size: Size {
            vcpus: s.vcpus,
            mem_mib: s.mem_mib,
            mem_max_mib: s.mem_max_mib,
            disk_gib: s.disk_gib,
        },
        egress,
        secrets: raw.secrets.names,
        rules_profile: raw.rules.profile,
        touch,
        idle_stop_mins: raw.idle.stop_after_mins,
    })
}

pub fn builtin() -> Vec<BoxTemplate> {
    vec![parse("claude-code", BUILTIN_CLAUDE_CODE).expect("built-in claude-code template is valid")]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    RootOwned,
    OwnedBy(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateWarning {
    pub file: PathBuf,
    pub reason: String,
}

/// Built-ins, replaced by same-named files in `dir`; sorted by name. Bad files
/// are skipped with a warning; a missing directory yields the built-ins only.
pub fn load_dir(dir: &Path, trust: Trust) -> (Vec<BoxTemplate>, Vec<TemplateWarning>) {
    let mut map: BTreeMap<String, BoxTemplate> =
        builtin().into_iter().map(|t| (t.name.clone(), t)).collect();
    let mut warnings = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (sorted(map), warnings),
        Err(e) => {
            warnings.push(TemplateWarning {
                file: dir.to_path_buf(),
                reason: format!("cannot read directory: {e}"),
            });
            return (sorted(map), warnings);
        }
    };
    let mut paths: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();
    for path in paths {
        match load_file(&path, trust) {
            Ok(t) => {
                map.insert(t.name.clone(), t);
            }
            Err(reason) => warnings.push(TemplateWarning { file: path, reason }),
        }
    }
    (sorted(map), warnings)
}

fn sorted(map: BTreeMap<String, BoxTemplate>) -> Vec<BoxTemplate> {
    map.into_values().collect()
}

#[cfg(unix)]
fn load_file(path: &Path, trust: Trust) -> Result<BoxTemplate, String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("file name is not UTF-8")?;
    let lmeta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if lmeta.file_type().is_symlink() {
        return Err("refusing a symlink".into());
    }
    if !lmeta.is_file() {
        return Err("not a regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.dev() != lmeta.dev() || meta.ino() != lmeta.ino() {
        return Err("file changed while opening".into());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    match trust {
        Trust::RootOwned if meta.uid() != 0 => return Err("not owned by root".into()),
        Trust::OwnedBy(uid) if meta.uid() != uid => return Err(format!("not owned by uid {uid}")),
        _ => {}
    }
    if meta.mode() & 0o022 != 0 {
        return Err("group- or world-writable".into());
    }
    let mut buf = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    let text = String::from_utf8(buf).map_err(|_| "not UTF-8".to_string())?;
    parse(stem, &text)
}

#[cfg(not(unix))]
fn load_file(path: &Path, trust: Trust) -> Result<BoxTemplate, String> {
    let _ = (path, trust, MAX_FILE_BYTES);
    Err("template files are not trusted on this platform".into())
}
