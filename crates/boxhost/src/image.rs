//! The box base image: the build recipe with pinned inputs, and the manifest
//! that describes a built base image.

use serde::{Deserialize, Serialize};

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

/// What a box without a default image is told (R43). Plan 36 Task 5 drops
/// the part after the semicolon once `image import --default` is built.
pub const DEFAULT_IMAGE_HINT: &str = "make one with \"saiife box image build\"; making it the default (\"saiife box image import --default <path>\") is not in this build yet";

pub const DEFAULT_RECIPE: &str = include_str!("../../../assets/box/recipe.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecipe {
    ubuntu: RawUbuntu,
    packages: RawPackages,
    images: RawImages,
    claude: RawClaude,
    boot: RawBoot,
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

/// Parses and validates a recipe. The Claude Code pin must be set.
pub fn parse_recipe(text: &str) -> Result<Recipe, String> {
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
    pub packages: Vec<ManifestPackage>,
    pub images: Vec<PinnedImage>,
    pub boot: ManifestBoot,
    pub signature: Option<String>,
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
