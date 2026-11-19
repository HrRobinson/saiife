//! The box base image: the build recipe with pinned inputs, and the manifest
//! that describes a built base image.

pub use saiife_boxes::template::AgentKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod store;
pub mod ubuntu;

pub use store::Store;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub ubuntu_release: String,
    pub ubuntu_sha256: String,
    pub packages: Vec<String>,
    pub images: Vec<PinnedImage>,
    pub claude: ClaudePin,
    pub direct_kernel: bool,
    /// Plan 42 D9: `Some` only when `[codex]` is enabled (in the recipe
    /// or with `--with codex`) and every field is valid.
    pub codex: Option<AgentPin>,
    /// Plan 42 D9: the Gemini CLI bundle and the Node.js it runs on.
    pub gemini: Option<GeminiPin>,
}

/// A pinned optional agent download (plan 42 D9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPin {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiPin {
    pub cli: AgentPin,
    pub node: AgentPin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedImage {
    pub name: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudePin {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

/// What a box without a default image is told (R43): build one, then
/// import it as the default (plan 36 Task 5).
pub const DEFAULT_IMAGE_HINT: &str =
    "make one with \"saiife box image build\", then \"saiife box image import --default <path>\"";

pub const DEFAULT_RECIPE: &str = include_str!("../../../assets/box/recipe.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecipe {
    ubuntu: RawUbuntu,
    packages: RawPackages,
    images: RawImages,
    claude: RawClaude,
    #[serde(default)]
    codex: Option<RawCodex>,
    #[serde(default)]
    gemini: Option<RawGemini>,
    boot: RawBoot,
}
/// Free text on purpose: a disabled section is never validated (D9).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCodex {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    version: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGemini {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    version: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    node_version: String,
    #[serde(default)]
    node_url: String,
    #[serde(default)]
    node_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUbuntu {
    release: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackages {
    apt: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImages {
    pull: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaude {
    version: String,
    url: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBoot {
    direct_kernel: bool,
}

const UNPINNED: &str = "UNPINNED";

pub(crate) fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn valid_apt_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    let first = b[0].is_ascii_lowercase() || b[0].is_ascii_digit();
    first
        && b[1..].iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'.' | b'-')
        })
}

pub(crate) fn parse_pinned_image(s: &str) -> Result<PinnedImage, String> {
    let (name, digest) = s
        .split_once("@sha256:")
        .ok_or_else(|| format!("images.pull: {s:?} must be name@sha256:<64 hex>"))?;
    if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("images.pull: bad image name in {s:?}"));
    }
    if !is_sha256(digest) {
        return Err(format!(
            "images.pull: digest in {s:?} must be 64 lowercase hex"
        ));
    }
    Ok(PinnedImage {
        name: name.to_string(),
        digest: format!("sha256:{digest}"),
    })
}

/// One enabled agent pin (D9): no field `UNPINNED`, then the sha256, url
/// and version rules. `section.prefix` names the fields (`codex.`,
/// `gemini.node_`), `what` the release to pin.
#[allow(clippy::too_many_arguments)]
fn agent_pin(
    section: &str,
    prefix: &str,
    what: &str,
    suffix: &str,
    version: String,
    url: String,
    sha256: String,
) -> Result<AgentPin, String> {
    let field = |f: &str| format!("{section}.{prefix}{f}");
    for (f, v) in [("sha256", &sha256), ("version", &version), ("url", &url)] {
        if v == UNPINNED {
            return Err(format!(
                "{} is UNPINNED; pin the {what} release first (or set {section}.enabled = false)",
                field(f)
            ));
        }
    }
    if !is_sha256(&sha256) {
        return Err(format!("{} must be 64 lowercase hex", field("sha256")));
    }
    if !url.starts_with("https://") {
        return Err(format!("{} must start with https://", field("url")));
    }
    if !url.ends_with(suffix) {
        return Err(format!("{} must end with {suffix}", field("url")));
    }
    if version.is_empty() {
        return Err(format!("{} must not be empty", field("version")));
    }
    Ok(AgentPin {
        version,
        url,
        sha256,
    })
}

/// Parses and validates a recipe. The Claude Code pin must be set; the
/// optional agents stay off (plan 42 D9).
pub fn parse_recipe(text: &str) -> Result<Recipe, String> {
    parse_recipe_with(text, &[])
}

/// Like [`parse_recipe`], with the `[codex]` / `[gemini]` sections named
/// in `with` turned on for this build (`--with`, D9). A disabled section
/// is not validated; an enabled one must be fully pinned. Claude Code is
/// always in the image and cannot be named.
pub fn parse_recipe_with(text: &str, with: &[AgentKind]) -> Result<Recipe, String> {
    if with.contains(&AgentKind::ClaudeCode) {
        return Err("claude-code is always in the image; --with takes codex or gemini".into());
    }
    let raw: RawRecipe = toml::from_str(text).map_err(|e| format!("recipe: {e}"))?;
    if !is_sha256(&raw.ubuntu.sha256) {
        return Err("ubuntu.sha256 must be 64 lowercase hex".into());
    }
    if raw.ubuntu.release.is_empty() {
        return Err("ubuntu.release must not be empty".into());
    }
    for p in &raw.packages.apt {
        if !valid_apt_name(p) {
            return Err(format!("packages.apt: bad package name {p:?}"));
        }
    }
    let images = raw
        .images
        .pull
        .iter()
        .map(|s| parse_pinned_image(s))
        .collect::<Result<Vec<_>, _>>()?;
    let c = raw.claude;
    if c.sha256 == UNPINNED {
        return Err("claude.sha256 is UNPINNED; pin the Claude Code release first".into());
    }
    if c.version == UNPINNED {
        return Err("claude.version is UNPINNED; pin the Claude Code release first".into());
    }
    if c.url == UNPINNED {
        return Err("claude.url is UNPINNED; pin the Claude Code release first".into());
    }
    if !is_sha256(&c.sha256) {
        return Err("claude.sha256 must be 64 lowercase hex".into());
    }
    if !c.url.starts_with("https://") {
        return Err("claude.url must start with https://".into());
    }
    if c.version.is_empty() {
        return Err("claude.version must not be empty".into());
    }
    // A section missing from the recipe reads as all UNPINNED when --with
    // turns it on.
    let codex_raw = raw.codex.unwrap_or_else(|| RawCodex {
        enabled: false,
        version: UNPINNED.into(),
        url: UNPINNED.into(),
        sha256: UNPINNED.into(),
    });
    let codex = if codex_raw.enabled || with.contains(&AgentKind::Codex) {
        Some(agent_pin(
            "codex",
            "",
            "Codex",
            ".tar.gz",
            codex_raw.version,
            codex_raw.url,
            codex_raw.sha256,
        )?)
    } else {
        None
    };
    let gemini_raw = raw.gemini.unwrap_or_else(|| RawGemini {
        enabled: false,
        version: UNPINNED.into(),
        url: UNPINNED.into(),
        sha256: UNPINNED.into(),
        node_version: UNPINNED.into(),
        node_url: UNPINNED.into(),
        node_sha256: UNPINNED.into(),
    });
    let gemini = if gemini_raw.enabled || with.contains(&AgentKind::Gemini) {
        let g = gemini_raw;
        Some(GeminiPin {
            cli: agent_pin(
                "gemini",
                "",
                "Gemini CLI",
                ".zip",
                g.version,
                g.url,
                g.sha256,
            )?,
            node: agent_pin(
                "gemini",
                "node_",
                "Node.js",
                ".tar.xz",
                g.node_version,
                g.node_url,
                g.node_sha256,
            )?,
        })
    } else {
        None
    };
    Ok(Recipe {
        ubuntu_release: raw.ubuntu.release,
        ubuntu_sha256: raw.ubuntu.sha256,
        packages: raw.packages.apt,
        images,
        claude: ClaudePin {
            version: c.version,
            url: c.url,
            sha256: c.sha256,
        },
        direct_kernel: raw.boot.direct_kernel,
        codex,
        gemini,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUbuntu {
    pub release: String,
    pub image_sha256: String,
    pub sums_signer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestVmm {
    pub ch_version: String,
    pub ch_sha256: String,
    pub fw_version: String,
    pub fw_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPin {
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifestBoot {
    Firmware,
    Kernel {
        kernel: String,
        sha256: String,
        cmdline: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub id: String,
    pub sha256: String,
    pub virtual_gib: u64,
    pub actual_bytes: u64,
    pub built_at: String,
    pub builder: String,
    pub recipe_sha256: String,
    pub ubuntu: ManifestUbuntu,
    pub vmm: ManifestVmm,
    pub saiife: ManifestPin,
    pub claude: ManifestPin,
    /// Plan 42 D10: the optional agents baked in (`codex`, `gemini`,
    /// `node`). Left out when empty, so a manifest written before plan 42
    /// keeps its exact JSON (and any signature over it).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, ManifestPin>,
    /// What the bake put in the image beyond its pins (FU2):
    /// [`CLAUDE_MANAGED_SETTINGS`] when Claude Code's managed settings
    /// (saiife's hooks) are baked in. Left out when empty, so an older
    /// manifest keeps its exact JSON (and any signature over it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    pub packages: Vec<ManifestPackage>,
    pub images: Vec<PinnedImage>,
    pub boot: ManifestBoot,
    pub signature: Option<String>,
}

/// The keys of `Manifest::agents` (plan 42 fixed values).
pub const MANIFEST_AGENTS: [&str; 3] = ["codex", "gemini", "node"];

/// The capability of an image whose Claude Code hooks are in its root-owned
/// managed settings (FU2). Setup no longer sends them per boot, so a Claude
/// Code box on an image without it would run with no saiife hook.
pub const CLAUDE_MANAGED_SETTINGS: &str = "claude_managed_settings";

/// The values of `Manifest::capabilities` this saiife knows.
pub const MANIFEST_CAPABILITIES: [&str; 1] = [CLAUDE_MANAGED_SETTINGS];

impl Manifest {
    /// The agents a box on this image can run (D10, FU2): Claude Code when
    /// its managed settings are baked in, Codex when baked in, Gemini only
    /// with its Node runtime.
    pub fn agent_names(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self
            .capabilities
            .iter()
            .any(|c| c == CLAUDE_MANAGED_SETTINGS)
        {
            v.push(AgentKind::ClaudeCode.name().to_string());
        }
        if self.agents.contains_key("codex") {
            v.push(AgentKind::Codex.name().to_string());
        }
        if self.agents.contains_key("gemini") && self.agents.contains_key("node") {
            v.push(AgentKind::Gemini.name().to_string());
        }
        v
    }
}

/// The image id for a base image with this content hash.
pub fn image_id(sha256: &str) -> String {
    format!("base-{sha256}")
}

/// Returns the sha256 of a `base-<64 hex>` image id.
pub fn parse_image_id(s: &str) -> Result<String, String> {
    match s.strip_prefix("base-") {
        Some(h) if is_sha256(h) => Ok(h.to_string()),
        _ => Err(format!("bad image id {s:?}: want base-<64 lowercase hex>")),
    }
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, String> {
        let m: Manifest = serde_json::from_str(text).map_err(|e| format!("manifest: {e}"))?;
        if m.version != 1 {
            return Err(format!("manifest version {} is not supported", m.version));
        }
        if !is_sha256(&m.sha256) {
            return Err("manifest sha256 must be 64 lowercase hex".into());
        }
        if m.id != image_id(&m.sha256) {
            return Err("manifest id does not match its sha256".into());
        }
        let digests = [
            ("recipe_sha256", &m.recipe_sha256),
            ("ubuntu.image_sha256", &m.ubuntu.image_sha256),
            ("vmm.ch_sha256", &m.vmm.ch_sha256),
            ("vmm.fw_sha256", &m.vmm.fw_sha256),
            ("saiife.sha256", &m.saiife.sha256),
            ("claude.sha256", &m.claude.sha256),
        ];
        for (field, v) in digests {
            if !is_sha256(v) {
                return Err(format!("manifest {field} must be 64 lowercase hex"));
            }
        }
        for (k, pin) in &m.agents {
            if !MANIFEST_AGENTS.contains(&k.as_str()) {
                return Err(format!(
                    "manifest agents: unknown agent {k:?} (want codex, gemini or node)"
                ));
            }
            if !is_sha256(&pin.sha256) {
                return Err(format!(
                    "manifest agents.{k}.sha256 must be 64 lowercase hex"
                ));
            }
        }
        for c in &m.capabilities {
            if !MANIFEST_CAPABILITIES.contains(&c.as_str()) {
                return Err(format!(
                    "manifest capabilities: unknown capability {c:?} (want {CLAUDE_MANAGED_SETTINGS})"
                ));
            }
        }
        if !ubuntu::is_fpr(&m.ubuntu.sums_signer) {
            return Err("manifest ubuntu.sums_signer must be 40 uppercase hex".into());
        }
        for i in &m.images {
            let ok = i.digest.strip_prefix("sha256:").is_some_and(is_sha256);
            if !ok || i.name.is_empty() {
                return Err(format!(
                    "manifest images: {:?} must have a sha256:<64 hex> digest",
                    i.name
                ));
            }
        }
        if let ManifestBoot::Kernel { kernel, sha256, .. } = &m.boot {
            if *kernel != format!("{}.vmlinuz", m.id) {
                return Err(format!(
                    "manifest boot.kernel must be {}.vmlinuz, not {kernel:?}",
                    m.id
                ));
            }
            if !is_sha256(sha256) {
                return Err("manifest boot.sha256 must be 64 lowercase hex".into());
            }
        }
        Ok(m)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serializes")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Image import exists (plan 36 Task 5): the hint names it as a step,
    /// never as missing from the build.
    #[test]
    fn default_image_hint_names_the_import() {
        assert!(!DEFAULT_IMAGE_HINT.contains("not in this build"));
        assert!(DEFAULT_IMAGE_HINT.contains("saiife box image build"));
        assert!(DEFAULT_IMAGE_HINT.contains("saiife box image import --default <path>"));
    }

    fn hex(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn pinned_text() -> String {
        DEFAULT_RECIPE
            .replace("version = \"UNPINNED\"", "version = \"0.0.0-test\"")
            .replace(
                "url = \"UNPINNED\"",
                "url = \"https://example.invalid/claude\"",
            )
            .replace(
                "sha256 = \"UNPINNED\"",
                &format!("sha256 = \"{}\"", "a".repeat(64)),
            )
    }

    #[test]
    fn default_recipe_parses_but_claude_is_unpinned() {
        let e = parse_recipe(DEFAULT_RECIPE).unwrap_err();
        assert!(e.contains("claude.sha256"), "{e}");
    }

    #[test]
    fn pinned_recipe_parses() {
        let r = parse_recipe(&pinned_text()).unwrap();
        assert_eq!(r.ubuntu_release, "release-20261017");
        assert_eq!(r.claude.sha256, "a".repeat(64));
        assert!(r.packages.contains(&"socat".to_string()));
        assert!(r.images.is_empty());
        assert!(!r.direct_kernel);
    }

    #[test]
    fn tag_without_digest_is_refused() {
        let t = pinned_text().replace("pull = []", "pull = [\"busybox:1.36\"]");
        let e = parse_recipe(&t).unwrap_err();
        assert!(
            e.contains("images.pull") && e.contains("busybox:1.36"),
            "{e}"
        );
    }

    #[test]
    fn digest_must_be_64_hex() {
        let t = pinned_text().replace("pull = []", "pull = [\"busybox@sha256:abc\"]");
        assert!(parse_recipe(&t).is_err());
        let ok = pinned_text().replace(
            "pull = []",
            &format!("pull = [\"busybox@sha256:{}\"]", "b".repeat(64)),
        );
        let r = parse_recipe(&ok).unwrap();
        assert_eq!(r.images[0].name, "busybox");
        assert_eq!(r.images[0].digest, format!("sha256:{}", "b".repeat(64)));
    }

    #[test]
    fn bad_apt_name_is_refused() {
        let t = pinned_text().replace("\"socat\"", "\"x; rm -rf /\"");
        assert!(parse_recipe(&t).unwrap_err().contains("package"));
    }

    #[test]
    fn unknown_key_is_refused() {
        let t = pinned_text().replace("[boot]", "[boot]\nextra = 1");
        assert!(parse_recipe(&t).is_err());
        let t = format!("{}\n[more]\nx = 1\n", pinned_text());
        assert!(parse_recipe(&t).is_err());
    }

    /// The shipped recipe with only its `[claude]` section pinned.
    fn claude_pinned_default() -> String {
        let (head, tail) = DEFAULT_RECIPE.split_once("[claude]\n").unwrap();
        let rest = tail.split_once("\n[").map_or("", |(_, r)| r);
        format!(
            "{head}[claude]\nversion = \"0.0.0-test\"\nurl = \"https://example.invalid/claude\"\nsha256 = \"{}\"\n[{rest}",
            "a".repeat(64)
        )
    }

    const CODEX_URL: &str = "https://example.invalid/codex-x86_64-unknown-linux-musl.tar.gz";
    const GEMINI_URL: &str = "https://example.invalid/gemini-cli-bundle.zip";
    const NODE_URL: &str = "https://example.invalid/node-v0-linux-x64.tar.xz";

    /// Plan 36's recipe text: no `[codex]` or `[gemini]` section.
    fn plan36_text() -> String {
        format!(
            "[ubuntu]\nrelease = \"release-20261017\"\nsha256 = \"{}\"\n[packages]\napt = [\"socat\"]\n[images]\npull = []\n[claude]\nversion = \"1\"\nurl = \"https://example.invalid/claude\"\nsha256 = \"{}\"\n[boot]\ndirect_kernel = false\n",
            hex('0'),
            hex('a')
        )
    }

    fn codex_section(enabled: bool, version: &str, url: &str, sha: &str) -> String {
        format!("[codex]\nenabled = {enabled}\nversion = \"{version}\"\nurl = \"{url}\"\nsha256 = \"{sha}\"\n")
    }

    #[allow(clippy::too_many_arguments)]
    fn gemini_section(
        enabled: bool,
        version: &str,
        url: &str,
        sha: &str,
        node_version: &str,
        node_url: &str,
        node_sha: &str,
    ) -> String {
        format!(
            "[gemini]\nenabled = {enabled}\nversion = \"{version}\"\nurl = \"{url}\"\nsha256 = \"{sha}\"\nnode_version = \"{node_version}\"\nnode_url = \"{node_url}\"\nnode_sha256 = \"{node_sha}\"\n"
        )
    }

    fn pinned_codex() -> String {
        codex_section(true, "0.1.0", CODEX_URL, &hex('c'))
    }

    fn pinned_gemini() -> String {
        gemini_section(
            true,
            "0.2.0",
            GEMINI_URL,
            &hex('9'),
            "22.0.0",
            NODE_URL,
            &hex('8'),
        )
    }

    #[test]
    fn default_recipe_parses_without_agents() {
        let r = parse_recipe(&claude_pinned_default()).unwrap();
        assert_eq!(r.codex, None);
        assert_eq!(r.gemini, None);
        // The shipped sections are there, off and UNPINNED (D9).
        for l in [
            "[codex]\nenabled = false\n",
            "[gemini]\nenabled = false\n",
            "node_sha256 = \"UNPINNED\"",
        ] {
            assert!(DEFAULT_RECIPE.contains(l), "{l}");
        }
    }

    #[test]
    fn enabled_unpinned_is_refused() {
        let codex_fields = ["version", "url", "sha256"];
        for f in codex_fields {
            let v = |name: &str, good: &str| {
                if name == f {
                    UNPINNED.to_string()
                } else {
                    good.to_string()
                }
            };
            let t = format!(
                "{}{}",
                plan36_text(),
                codex_section(
                    true,
                    &v("version", "0.1.0"),
                    &v("url", CODEX_URL),
                    &v("sha256", &hex('c'))
                )
            );
            let e = parse_recipe(&t).unwrap_err();
            assert_eq!(
                e,
                format!(
                    "codex.{f} is UNPINNED; pin the Codex release first (or set codex.enabled = false)"
                )
            );
        }
        let gemini_fields = [
            ("version", "Gemini CLI"),
            ("url", "Gemini CLI"),
            ("sha256", "Gemini CLI"),
            ("node_version", "Node.js"),
            ("node_url", "Node.js"),
            ("node_sha256", "Node.js"),
        ];
        for (f, what) in gemini_fields {
            let v = |name: &str, good: &str| {
                if name == f {
                    UNPINNED.to_string()
                } else {
                    good.to_string()
                }
            };
            let t = format!(
                "{}{}",
                plan36_text(),
                gemini_section(
                    true,
                    &v("version", "0.2.0"),
                    &v("url", GEMINI_URL),
                    &v("sha256", &hex('9')),
                    &v("node_version", "22.0.0"),
                    &v("node_url", NODE_URL),
                    &v("node_sha256", &hex('8')),
                )
            );
            let e = parse_recipe(&t).unwrap_err();
            assert_eq!(
                e,
                format!(
                    "gemini.{f} is UNPINNED; pin the {what} release first (or set gemini.enabled = false)"
                )
            );
        }
        // The shipped recipe with --with codex: the D9 example text.
        let e = parse_recipe_with(&claude_pinned_default(), &[AgentKind::Codex]).unwrap_err();
        assert_eq!(
            e,
            "codex.sha256 is UNPINNED; pin the Codex release first (or set codex.enabled = false)"
        );
        let e = parse_recipe_with(&claude_pinned_default(), &[AgentKind::Gemini]).unwrap_err();
        assert!(e.starts_with("gemini.sha256 is UNPINNED"), "{e}");
    }

    #[test]
    fn disabled_section_is_ignored() {
        let t = format!(
            "{}{}{}",
            plan36_text(),
            codex_section(false, "", "ftp://x y", "nope"),
            gemini_section(false, "", "http://a", "zz", "", "file:///x", "UNPINNED")
        );
        let r = parse_recipe(&t).unwrap();
        assert_eq!((r.codex, r.gemini), (None, None));
        // A section with only `enabled = false`, or with no `enabled` at all.
        let t = format!("{}[codex]\nenabled = false\n[gemini]\n", plan36_text());
        let r = parse_recipe(&t).unwrap();
        assert_eq!((r.codex, r.gemini), (None, None));
        // An unknown key is still refused.
        let t = format!("{}[codex]\nenabled = false\nextra = 1\n", plan36_text());
        assert!(parse_recipe(&t).is_err());
    }

    #[test]
    fn with_enables_a_section() {
        let t = format!(
            "{}{}{}",
            plan36_text(),
            codex_section(false, "0.1.0", CODEX_URL, &hex('c')),
            pinned_gemini().replace("enabled = true", "enabled = false")
        );
        let r = parse_recipe(&t).unwrap();
        assert_eq!((r.codex.clone(), r.gemini.clone()), (None, None));
        let r = parse_recipe_with(&t, &[AgentKind::Codex]).unwrap();
        assert_eq!(
            r.codex,
            Some(AgentPin {
                version: "0.1.0".into(),
                url: CODEX_URL.into(),
                sha256: hex('c'),
            })
        );
        assert_eq!(r.gemini, None);
        let r = parse_recipe_with(&t, &[AgentKind::Gemini, AgentKind::Codex]).unwrap();
        assert!(r.codex.is_some());
        assert_eq!(
            r.gemini,
            Some(GeminiPin {
                cli: AgentPin {
                    version: "0.2.0".into(),
                    url: GEMINI_URL.into(),
                    sha256: hex('9'),
                },
                node: AgentPin {
                    version: "22.0.0".into(),
                    url: NODE_URL.into(),
                    sha256: hex('8'),
                },
            })
        );
        // `enabled = true` in the file needs no --with.
        let t = format!("{}{}{}", plan36_text(), pinned_codex(), pinned_gemini());
        let r = parse_recipe(&t).unwrap();
        assert!(r.codex.is_some() && r.gemini.is_some());
        // --with on a recipe without the section: everything is UNPINNED.
        let e = parse_recipe_with(&plan36_text(), &[AgentKind::Codex]).unwrap_err();
        assert!(e.starts_with("codex.sha256 is UNPINNED"), "{e}");
        // Claude Code is not an optional agent.
        assert!(parse_recipe_with(&plan36_text(), &[AgentKind::ClaudeCode]).is_err());
    }

    #[test]
    fn agent_url_rules() {
        let base = plan36_text();
        let codex = |url: &str, sha: &str, version: &str| {
            parse_recipe(&format!("{base}{}", codex_section(true, version, url, sha)))
        };
        let e = codex(&CODEX_URL.replace("https://", "http://"), &hex('c'), "1").unwrap_err();
        assert_eq!(e, "codex.url must start with https://");
        let e = codex(&CODEX_URL.replace(".tar.gz", ".zip"), &hex('c'), "1").unwrap_err();
        assert_eq!(e, "codex.url must end with .tar.gz");
        let e = codex(CODEX_URL, &"C".repeat(64), "1").unwrap_err();
        assert_eq!(e, "codex.sha256 must be 64 lowercase hex");
        let e = codex(CODEX_URL, &hex('c'), "").unwrap_err();
        assert_eq!(e, "codex.version must not be empty");
        let gem = |url: &str, node_url: &str| {
            parse_recipe(&format!(
                "{base}{}",
                gemini_section(true, "1", url, &hex('9'), "22", node_url, &hex('8'))
            ))
        };
        assert!(gem(GEMINI_URL, NODE_URL).is_ok());
        let e = gem(&GEMINI_URL.replace(".zip", ".tar.gz"), NODE_URL).unwrap_err();
        assert_eq!(e, "gemini.url must end with .zip");
        let e = gem(&GEMINI_URL.replace("https://", "http://"), NODE_URL).unwrap_err();
        assert_eq!(e, "gemini.url must start with https://");
        let e = gem(GEMINI_URL, &NODE_URL.replace(".tar.xz", ".tar.gz")).unwrap_err();
        assert_eq!(e, "gemini.node_url must end with .tar.xz");
        let e = gem(GEMINI_URL, &NODE_URL.replace("https://", "http://")).unwrap_err();
        assert_eq!(e, "gemini.node_url must start with https://");
    }

    #[test]
    fn recipe_without_sections_parses() {
        let r = parse_recipe(&plan36_text()).unwrap();
        assert_eq!(r.claude.version, "1");
        assert_eq!((r.codex, r.gemini), (None, None));
    }

    /// A plan 36 manifest, as `to_json` wrote it before plan 42, signed.
    fn plan36_manifest_json() -> String {
        let mut m = manifest();
        m.signature = Some("c2lnbmF0dXJl".into());
        // a plan-36 image predates FU2's capabilities
        m.capabilities.clear();
        let json = m.to_json();
        assert!(!json.contains("agents"), "{json}");
        assert!(!json.contains("capabilities"), "{json}");
        json
    }

    #[test]
    fn old_manifest_round_trips() {
        // A literal plan-36 manifest (no `agents` key), not built by the
        // serializer under test.
        let json = r#"{
  "version": 1,
  "id": "base-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "virtual_gib": 20,
  "actual_bytes": 1234,
  "built_at": "2026-01-01T00:00:00Z",
  "builder": "saiife 0.0.0",
  "recipe_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "ubuntu": {
    "release": "release-20261017",
    "image_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "sums_signer": "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
  },
  "vmm": {
    "ch_version": "v0",
    "ch_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "fw_version": "v0",
    "fw_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
  },
  "saiife": {
    "version": "0.0.0",
    "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
  },
  "claude": {
    "version": "0.0.0",
    "sha256": "4444444444444444444444444444444444444444444444444444444444444444"
  },
  "packages": [
    {
      "name": "socat",
      "version": "1.0"
    }
  ],
  "images": [
    {
      "name": "busybox",
      "digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    }
  ],
  "boot": {
    "kernel": {
      "kernel": "base-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.vmlinuz",
      "sha256": "6666666666666666666666666666666666666666666666666666666666666666",
      "cmdline": "console=ttyS0"
    }
  },
  "signature": "c2lnbmF0dXJl"
}"#;
        assert_eq!(json, plan36_manifest_json(), "the golden is current");
        let m = Manifest::parse(json).unwrap();
        assert!(m.agents.is_empty());
        assert!(m.capabilities.is_empty());
        // FU2: no managed Claude Code settings, so no Claude Code box
        assert!(m.agent_names().is_empty());
        let again = m.to_json();
        assert_eq!(again, json, "byte-identical");
        // A signature over these bytes still holds: the bytes are the same
        // and the signature itself is kept.
        assert_eq!(m.signature.as_deref(), Some("c2lnbmF0dXJl"));
    }

    /// FU2: the capability round-trips, lists Claude Code, and an unknown
    /// one is refused.
    #[test]
    fn manifest_capabilities() {
        let m = manifest();
        assert_eq!(m.capabilities, vec![CLAUDE_MANAGED_SETTINGS.to_string()]);
        assert_eq!(CLAUDE_MANAGED_SETTINGS, "claude_managed_settings");
        let json = m.to_json();
        assert!(
            json.contains("\"capabilities\": [\n    \"claude_managed_settings\"\n  ]"),
            "{json}"
        );
        let back = Manifest::parse(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.agent_names(), vec!["claude-code".to_string()]);
        let mut old = m.clone();
        old.capabilities.clear();
        assert!(old.agent_names().is_empty());
        let mut bad = m;
        bad.capabilities.push("root_shell".into());
        let e = Manifest::parse(&bad.to_json()).unwrap_err();
        assert!(e.contains("unknown capability \"root_shell\""), "{e}");
    }

    #[test]
    fn manifest_lists_agents() {
        let mut m = manifest();
        let pin = |v: &str, c: char| ManifestPin {
            version: v.into(),
            sha256: hex(c),
        };
        m.agents.insert("codex".into(), pin("0.1.0", '7'));
        m.agents.insert("gemini".into(), pin("0.2.0", '8'));
        m.agents.insert("node".into(), pin("22.0.0", '9'));
        let json = m.to_json();
        assert!(json.contains("\"agents\": {"), "{json}");
        let back = Manifest::parse(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.agents["codex"].version, "0.1.0");
        // An unknown agent key or a bad digest is refused.
        let mut bad = m.clone();
        bad.agents.insert("cursor".into(), pin("1", '1'));
        assert!(Manifest::parse(&bad.to_json())
            .unwrap_err()
            .contains("cursor"));
        let mut bad = m.clone();
        bad.agents.get_mut("node").unwrap().sha256 = "x".into();
        assert!(Manifest::parse(&bad.to_json())
            .unwrap_err()
            .contains("agents.node.sha256"));
    }

    fn manifest() -> Manifest {
        let mut m = manifest_for(&hex('c'));
        m.boot = ManifestBoot::Kernel {
            kernel: format!("{}.vmlinuz", m.id),
            sha256: hex('6'),
            cmdline: "console=ttyS0".into(),
        };
        m
    }

    /// A valid firmware-boot manifest for an image with this digest.
    pub(crate) fn manifest_for(sha: &str) -> Manifest {
        Manifest {
            version: 1,
            id: image_id(sha),
            sha256: sha.to_string(),
            virtual_gib: 20,
            actual_bytes: 1234,
            built_at: "2026-01-01T00:00:00Z".into(),
            builder: "saiife 0.0.0".into(),
            recipe_sha256: hex('d'),
            ubuntu: ManifestUbuntu {
                release: "release-20261017".into(),
                image_sha256: hex('e'),
                sums_signer: ubuntu::UBUNTU_CLOUD_FPR.into(),
            },
            vmm: ManifestVmm {
                ch_version: "v0".into(),
                ch_sha256: hex('1'),
                fw_version: "v0".into(),
                fw_sha256: hex('2'),
            },
            saiife: ManifestPin {
                version: "0.0.0".into(),
                sha256: hex('3'),
            },
            claude: ManifestPin {
                version: "0.0.0".into(),
                sha256: hex('4'),
            },
            agents: BTreeMap::new(),
            capabilities: vec![CLAUDE_MANAGED_SETTINGS.into()],
            packages: vec![ManifestPackage {
                name: "socat".into(),
                version: "1.0".into(),
            }],
            images: vec![PinnedImage {
                name: "busybox".into(),
                digest: format!("sha256:{}", hex('5')),
            }],
            boot: ManifestBoot::Firmware,
            signature: None,
        }
    }

    #[test]
    fn manifest_roundtrip() {
        let m = manifest();
        let json = m.to_json();
        assert!(json.contains("\"signature\": null"));
        assert_eq!(Manifest::parse(&json).unwrap(), m);
        let mut f = manifest();
        f.boot = ManifestBoot::Firmware;
        f.signature = Some("sig".into());
        assert_eq!(Manifest::parse(&f.to_json()).unwrap(), f);
    }

    #[test]
    fn manifest_version_2_is_refused() {
        let mut m = manifest();
        m.version = 2;
        assert!(Manifest::parse(&m.to_json()).is_err());
        let mut m = manifest();
        m.id = image_id(&hex('f'));
        assert!(Manifest::parse(&m.to_json()).is_err());
        let json = manifest()
            .to_json()
            .replace("\"version\": 1,", "\"version\": 1, \"zz\": 1,");
        assert!(Manifest::parse(&json).is_err());
    }

    #[test]
    fn image_id_rules() {
        let h = hex('a');
        assert_eq!(image_id(&h), format!("base-{h}"));
        assert_eq!(parse_image_id(&image_id(&h)).unwrap(), h);
        assert!(parse_image_id("base-abc").is_err());
        assert!(parse_image_id(&format!("base-{}", "A".repeat(64))).is_err());
        assert!(parse_image_id(&h).is_err());
    }

    #[test]
    fn manifest_digests_are_checked() {
        type Edit = fn(&mut Manifest);
        let bad: [(&str, Edit); 10] = [
            ("recipe_sha256", |m| m.recipe_sha256 = "abc".into()),
            ("ubuntu.image_sha256", |m| {
                m.ubuntu.image_sha256 = "A".repeat(64)
            }),
            ("ubuntu.sums_signer", |m| {
                m.ubuntu.sums_signer = "d2eb".repeat(10)
            }),
            ("vmm.ch_sha256", |m| m.vmm.ch_sha256 = String::new()),
            ("vmm.fw_sha256", |m| m.vmm.fw_sha256 = "g".repeat(64)),
            ("saiife.sha256", |m| m.saiife.sha256 = "0".repeat(63)),
            ("claude.sha256", |m| m.claude.sha256 = "UNPINNED".into()),
            ("images", |m| m.images[0].digest = hex('5')),
            ("boot.sha256", |m| {
                if let ManifestBoot::Kernel { sha256, .. } = &mut m.boot {
                    *sha256 = "B".repeat(64);
                }
            }),
            ("boot.sha256", |m| {
                if let ManifestBoot::Kernel { sha256, .. } = &mut m.boot {
                    sha256.clear();
                }
            }),
        ];
        for (field, edit) in bad {
            let mut m = manifest();
            edit(&mut m);
            let e = Manifest::parse(&m.to_json()).unwrap_err();
            assert!(e.contains(field), "{field}: {e}");
        }
    }

    #[test]
    fn kernel_boot_rules() {
        let mut m = manifest();
        m.boot = ManifestBoot::Kernel {
            kernel: "vmlinuz".into(),
            sha256: hex('6'),
            cmdline: "console=ttyS0".into(),
        };
        assert!(Manifest::parse(&m.to_json())
            .unwrap_err()
            .contains("vmlinuz"));
        let json = manifest()
            .to_json()
            .replace("\"cmdline\":", "\"initrd\": \"x\", \"cmdline\":");
        assert!(json.contains("initrd"));
        assert!(Manifest::parse(&json).is_err());
    }
}
