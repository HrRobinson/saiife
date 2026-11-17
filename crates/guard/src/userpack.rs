//! Strict loading of user packs (`user.*`): any broken rule fails the whole
//! load (a user pack is a never-rule; dropping one silently would loosen it).

use std::fmt;
use std::path::{Component, Path};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::canon::{PathStyle, PathVars};
use crate::engine::Engine;
use crate::pack::{load_raw, parse_pack, valid_rule_id, Compile, Pack, PackWarning};
use crate::pack_raw::{RawPathRule, RawRule, RawSource, RawUnenforced};
pub use crate::pack_raw::{RuleAccess, RuleWhere, UnenforcedWhy};
use crate::pathrule::Access;
use crate::profile::Profile;
use crate::{AllowTrace, Decision};

pub const USER_PREFIX: &str = "user.";
pub const MAX_USER_RULES: usize = 128;

/// `user.` plus 1 to 48 of `[a-z0-9-]`, not starting with `-`.
pub fn valid_user_pack_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix(USER_PREFIX) else {
        return false;
    };
    (1..=48).contains(&rest.len())
        && !rest.starts_with('-')
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One user pack file: where it came from and its text.
#[derive(Debug, Clone, Copy)]
pub struct UserSrc<'a> {
    pub source: &'a str,
    pub text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPackError {
    pub source: String,
    pub message: String,
}

impl fmt::Display for UserPackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user pack {}: {}", self.source, self.message)
    }
}

impl std::error::Error for UserPackError {}

fn err(source: &str, message: impl Into<String>) -> UserPackError {
    UserPackError {
        source: source.to_string(),
        message: message.into(),
    }
}

/// Load every user pack, failing on the first problem (see the plan 32 spec).
pub fn load_user_packs(
    srcs: &[UserSrc],
    style: PathStyle,
    profile: Profile,
) -> Result<Vec<Pack>, UserPackError> {
    let mut out: Vec<Pack> = Vec::new();
    let mut total = 0usize;
    for s in srcs {
        let raw = parse_pack(s.text).map_err(|e| err(s.source, e.to_string()))?;
        check_keys(s.text).map_err(|m| err(s.source, m))?;
        check_rule_ids(&raw).map_err(|m| err(s.source, m))?;
        #[cfg(test)]
        crate::pack::note_compiled();
        let mut warnings: Vec<PackWarning> = Vec::new();
        let loaded = load_raw(
            s.source,
            &raw,
            style,
            profile,
            false,
            Compile::Now,
            &mut warnings,
        );
        // A dropped rule is the cause to report, even when it left no rules
        // (`NoRules`).
        if let Some(w) = warnings.iter().find(|w| w.dropped) {
            return Err(err(s.source, w.message.clone()));
        }
        let pack = loaded.map_err(|e| err(s.source, e.to_string()))?;
        let id = raw.pack.id.as_ref();
        if !valid_user_pack_id(id) {
            return Err(err(
                s.source,
                format!(
                    "invalid pack id {id:?}: use `user.` plus 1 to 48 of a-z, 0-9 or `-` (not first)"
                ),
            ));
        }
        if out.iter().any(|p| p.id == id) {
            return Err(err(s.source, format!("duplicate pack id {id:?}")));
        }
        if !raw.pack.default_on {
            return Err(err(s.source, "a user pack is always on; remove default_on"));
        }
        if raw.pack.lazy {
            return Err(err(s.source, "a user pack cannot be lazy"));
        }
        if raw.deny.iter().any(|r| r.id.is_none()) {
            return Err(err(s.source, "every [[deny]] in a user pack needs an id"));
        }
        // The engine reads a command only when it holds one of a pack's
        // triggers: command rules without any would almost never fire.
        let commands = raw
            .allow
            .iter()
            .chain(raw.deny.iter())
            .any(|r| r.platform.is_none_or(|p| p.applies_on(style)));
        if commands && pack.triggers.is_empty() {
            return Err(err(
                s.source,
                "a user pack with [[deny]] or [[allow]] rules needs triggers in [pack] (the commands it is about)",
            ));
        }
        total += pack.rule_count();
        if total > MAX_USER_RULES {
            return Err(err(
                s.source,
                format!("{total} rules in all user packs; the cap is {MAX_USER_RULES}"),
            ));
        }
        out.push(pack);
    }
    Ok(out)
}

/// The top-level keys a user pack may have.
const TOP_KEYS: &[&str] = &[
    "pack",
    "allow",
    "deny",
    "allow_path",
    "deny_path",
    "import",
    "unenforced",
];

/// The keys of a user pack's `[pack]` table.
const PACK_KEYS: &[&str] = &[
    "id",
    "name",
    "description",
    "default_on",
    "version",
    "triggers",
    "windows_triggers",
    "substitution_failsafe",
    "lazy",
];

/// An unknown key is an error in a user pack (a typo such as `[[deny_paths]]`
/// would drop its rules). The rule tables already refuse unknown keys.
fn check_keys(text: &str) -> Result<(), String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    if let Some(k) = table.keys().find(|k| !TOP_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "unknown key {k:?}; a user pack has only {}",
            TOP_KEYS.join(", ")
        ));
    }
    if let Some(meta) = table.get("pack").and_then(toml::Value::as_table) {
        if let Some(k) = meta.keys().find(|k| !PACK_KEYS.contains(&k.as_str())) {
            return Err(format!(
                "unknown key {k:?} in [pack]; it has only {}",
                PACK_KEYS.join(", ")
            ));
        }
    }
    Ok(())
}

/// A bad or repeated rule id is an error in a user pack (a built-in pack
/// keeps the rule and drops the id: D2 needs every user deny named).
fn check_rule_ids(raw: &crate::pack_raw::RawPackFile) -> Result<(), String> {
    for (kind, rules) in [("[[allow]]", &raw.allow), ("[[deny]]", &raw.deny)] {
        let mut seen = std::collections::HashSet::new();
        for id in rules.iter().filter_map(|r| r.id.as_deref()) {
            if !valid_rule_id(id) {
                return Err(format!(
                    "{kind} rule id {id:?}: use 1 to 64 of a-z, 0-9 or `-` (not first)"
                ));
            }
            if !seen.insert(id) {
                return Err(format!("{kind} rule id {id:?} is used twice"));
            }
        }
    }
    Ok(())
}

type Cached = Option<([u8; 32], Result<Vec<Pack>, UserPackError>)>;

/// The last load, kept so a hook that runs again on unchanged packs does not
/// recompile them.
static LAST: Mutex<Cached> = Mutex::new(None);

fn key(srcs: &[UserSrc], style: PathStyle, profile: Profile) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("{style:?}").as_bytes());
    h.update(b"\0");
    h.update(profile.name().as_bytes());
    h.update(b"\0");
    for s in srcs {
        h.update(s.source.as_bytes());
        h.update(b"\0");
        h.update(s.text.as_bytes());
        h.update(b"\0");
    }
    h.finalize().into()
}

/// [`load_user_packs`], with the last result kept for equal input.
pub fn load_user_packs_cached(
    srcs: &[UserSrc],
    style: PathStyle,
    profile: Profile,
) -> Result<Vec<Pack>, UserPackError> {
    let k = key(srcs, style, profile);
    let Ok(mut last) = LAST.lock() else {
        return load_user_packs(srcs, style, profile);
    };
    if let Some((lk, res)) = last.as_ref() {
        if *lk == k {
            return res.clone();
        }
    }
    let res = load_user_packs(srcs, style, profile);
    *last = Some((k, res.clone()));
    res
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRef {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub file: String,
    pub line: u32,
    pub line_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Deny,
    AllowPath(RuleAccess),
    DenyPath(RuleAccess),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRuleView {
    pub id: Option<String>,
    pub kind: RuleKind,
    /// The pattern or glob.
    pub text: String,
    pub reason: String,
    pub where_: RuleWhere,
    pub ask: bool,
    pub source: Option<SourceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnenforcedView {
    pub source: SourceRef,
    pub text: String,
    pub why: UnenforcedWhy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPackView {
    pub id: String,
    pub name: String,
    pub import: Option<ImportRef>,
    pub rules: Vec<UserRuleView>,
    pub unenforced: Vec<UnenforcedView>,
}

fn source_ref(s: &RawSource) -> SourceRef {
    SourceRef {
        file: s.file.to_string(),
        line: s.line,
        line_sha256: s.line_sha256.to_string(),
    }
}

fn unenforced_view(u: &RawUnenforced) -> UnenforcedView {
    UnenforcedView {
        source: source_ref(&u.source),
        text: u.text.to_string(),
        why: u.why,
    }
}

fn rule_view(r: &RawRule, kind: RuleKind) -> UserRuleView {
    UserRuleView {
        id: r.id.as_ref().map(|i| i.to_string()),
        kind,
        text: r.pattern.to_string(),
        reason: r.reason.as_deref().unwrap_or("").to_string(),
        where_: r.where_.unwrap_or(RuleWhere::Everywhere),
        ask: r.ask,
        source: r.source.as_ref().map(source_ref),
    }
}

fn path_view(r: &RawPathRule, kind: RuleKind) -> UserRuleView {
    UserRuleView {
        id: None,
        kind,
        text: r.glob.to_string(),
        reason: r.reason.as_deref().unwrap_or("").to_string(),
        where_: r.where_.unwrap_or(RuleWhere::Everywhere),
        ask: false,
        source: r.source.as_ref().map(source_ref),
    }
}

/// A user pack's text read for display: parsed, not compiled or checked
/// beyond its shape. A parse error names `<text>` as its source: the caller
/// has no file name, and a pack that does not parse has no id yet.
pub fn view(text: &str) -> Result<UserPackView, UserPackError> {
    let raw = parse_pack(text).map_err(|e| err("<text>", e.to_string()))?;
    let mut rules = Vec::new();
    for r in raw.allow.iter() {
        rules.push(rule_view(r, RuleKind::Allow));
    }
    for r in raw.deny.iter() {
        rules.push(rule_view(r, RuleKind::Deny));
    }
    for r in raw.allow_path.iter() {
        rules.push(path_view(r, RuleKind::AllowPath(r.access)));
    }
    for r in raw.deny_path.iter() {
        rules.push(path_view(r, RuleKind::DenyPath(r.access)));
    }
    Ok(UserPackView {
        id: raw.pack.id.to_string(),
        name: raw.pack.name.to_string(),
        import: raw.import.as_ref().map(|i| ImportRef {
            file: i.file.to_string(),
            sha256: i.sha256.to_string(),
        }),
        rules,
        unenforced: raw.unenforced.iter().map(unenforced_view).collect(),
    })
}

/// What happens to a rule inside a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxStatus {
    OffInBoxes,
    DiffReview,
    Advisory,
}

impl BoxStatus {
    pub fn label(self) -> &'static str {
        match self {
            BoxStatus::OffInBoxes => "off in boxes (host only)",
            BoxStatus::DiffReview => "checked at diff review",
            BoxStatus::Advisory => "advisory in boxes",
        }
    }
}

/// D8: a host-only rule is off in a box; an everywhere write-side path rule is
/// checked when the box's diff is reviewed; the rest advise. An `Allow*` is its
/// pack's carve-out and reported as advisory.
pub fn box_status(r: &UserRuleView) -> BoxStatus {
    if r.where_ == RuleWhere::Host {
        return BoxStatus::OffInBoxes;
    }
    match &r.kind {
        RuleKind::DenyPath(a) if *a != RuleAccess::Read => BoxStatus::DiffReview,
        _ => BoxStatus::Advisory,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffHit {
    pub path: String,
    pub pack: String,
    pub reason: String,
}

/// The changed paths of a box's diff that `packs` (loaded with
/// `Profile::Box`) forbid writing. A path that is absolute or climbs out with
/// `..` is a hit by itself: a diff path is never trusted.
pub fn diff_hits(
    packs: &[Pack],
    repo_root: &Path,
    home: &Path,
    rel_paths: &[&str],
) -> Vec<DiffHit> {
    let vars = PathVars::new()
        .with_cwd(repo_root)
        .with_var("PROJECT", repo_root)
        .with_var("HOME", home);
    let engine = Engine::new(packs.to_vec()).with_paths(vars);
    let mut out = Vec::new();
    for rel in rel_paths {
        let p = Path::new(rel);
        let escapes = p.is_absolute()
            || p.has_root()
            || p.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            });
        if escapes {
            out.push(DiffHit {
                path: (*rel).to_string(),
                pack: "saiife".to_string(),
                reason: "path leaves the repo".to_string(),
            });
            continue;
        }
        let full = repo_root.join(p);
        out.extend(diff_hit(
            rel,
            engine.evaluate_path(Access::Write, &full.to_string_lossy()),
        ));
    }
    out
}

/// The hit, if any, that `d` (the verdict on writing `rel`) makes. A path
/// the guard did not judge (out of time, or unresolvable) is a hit: the diff
/// is never passed unchecked.
fn diff_hit(rel: &str, d: Decision) -> Option<DiffHit> {
    let (pack, reason) = match d {
        Decision::Deny { pack, reason, .. } => (pack, reason),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout | AllowTrace::Unjudgeable { .. },
        } => ("saiife".to_string(), "not judged".to_string()),
        Decision::Allow { .. } => return None,
    };
    Some(DiffHit {
        path: rel.to_string(),
        pack,
        reason,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broad {
    /// The deny's pattern or glob.
    pub rule: String,
    /// The everyday command or path it denies.
    pub example: String,
}

pub const EVERYDAY_COMMANDS: &[&str] = &[
    "ls",
    "ls -la",
    "cat README.md",
    "cd src",
    "pwd",
    "echo hi",
    "git status",
    "git diff",
    "git log",
    "grep -r todo .",
    "cargo build",
    "cargo test",
    "npm test",
    "make",
    "python3 main.py",
];

pub const EVERYDAY_PATHS: &[(&str, Access)] = &[
    ("$PROJECT/src/main.rs", Access::Write),
    ("$PROJECT/README.md", Access::Read),
    ("~/notes.txt", Access::Read),
    ("/tmp/x", Access::Write),
];

const PROBE_HOME: &str = "/saiife-probe/home";
const PROBE_PROJECT: &str = "/saiife-probe/project";

/// Everyday commands and paths that `pack` denies: a rule that broad would
/// make the agent unusable, so the caller warns before it is saved.
pub fn broad_findings(pack: &Pack) -> Vec<Broad> {
    let vars = PathVars::new()
        .with_cwd(PROBE_PROJECT)
        .with_var("PROJECT", PROBE_PROJECT)
        .with_var("HOME", PROBE_HOME);
    let engine = Engine::new(vec![pack.clone()]).with_paths(vars);
    let mut out = Vec::new();
    for cmd in EVERYDAY_COMMANDS {
        if let Decision::Deny { pattern, .. } = engine.evaluate(cmd) {
            out.push(Broad {
                rule: pattern,
                example: (*cmd).to_string(),
            });
        }
    }
    for (p, access) in EVERYDAY_PATHS {
        let path = if let Some(rest) = p.strip_prefix("$PROJECT") {
            format!("{PROBE_PROJECT}{rest}")
        } else if let Some(rest) = p.strip_prefix('~') {
            format!("{PROBE_HOME}{rest}")
        } else {
            (*p).to_string()
        };
        if let Decision::Deny { pattern, .. } = engine.evaluate_path(*access, &path) {
            out.push(Broad {
                rule: pattern,
                example: path,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::compiled_packs;

    const A: &str = "[pack]\nid = \"user.a\"\ntriggers = [\"zz\"]\n[[deny]]\nid = \"d\"\npattern = '^zz$'\nreason = \"r\"\n";

    fn ids(r: Result<Vec<Pack>, UserPackError>) -> Vec<String> {
        r.unwrap().into_iter().map(|p| p.id).collect()
    }

    #[test]
    fn cache_hits_on_same_input() {
        let s1 = [UserSrc {
            source: "a",
            text: A,
        }];
        let before = compiled_packs();
        let first = ids(load_user_packs_cached(&s1, PathStyle::Posix, Profile::Host));
        assert_eq!(first, ["user.a"]);
        assert_eq!(compiled_packs(), before + 1);
        let again = ids(load_user_packs_cached(&s1, PathStyle::Posix, Profile::Host));
        assert_eq!(again, first);
        assert_eq!(compiled_packs(), before + 1, "a hit compiles nothing");
        let text2 = A.replace("user.a", "user.b");
        let s2 = [UserSrc {
            source: "a",
            text: &text2,
        }];
        let third = ids(load_user_packs_cached(&s2, PathStyle::Posix, Profile::Host));
        assert_eq!(third, ["user.b"]);
        assert_eq!(compiled_packs(), before + 2);
        // The profile is part of the key.
        let _ = load_user_packs_cached(&s2, PathStyle::Posix, Profile::Box);
        assert_eq!(compiled_packs(), before + 3);
    }

    #[test]
    fn id_shape() {
        assert!(valid_user_pack_id("user.a-1"));
        assert!(!valid_user_pack_id("user."));
        assert!(!valid_user_pack_id("user.-a"));
        assert!(!valid_user_pack_id(&format!("user.{}", "a".repeat(49))));
        assert!(valid_user_pack_id(&format!("user.{}", "a".repeat(48))));
    }

    const FULL: &str = r#"
[pack]
id = "user.t"
name = "T"
triggers = ["zz"]
[import]
file = "CLAUDE.md"
sha256 = "ab"
[[deny]]
id = "d"
pattern = '^zz$'
reason = "r"
where = "host"
ask = true
[[deny_path]]
glob = "$PROJECT/x"
access = "write"
reason = "p"
[[unenforced]]
text = "be nice"
why = "judgement"
[unenforced.source]
file = "CLAUDE.md"
line = 3
line_sha256 = "cd"
"#;

    #[test]
    fn view_reads_every_key() {
        let v = view(FULL).unwrap();
        assert_eq!(v.id, "user.t");
        assert_eq!(v.name, "T");
        assert_eq!(
            v.import,
            Some(ImportRef {
                file: "CLAUDE.md".into(),
                sha256: "ab".into()
            })
        );
        assert_eq!(v.rules.len(), 2);
        let d = &v.rules[0];
        assert_eq!(d.id.as_deref(), Some("d"));
        assert_eq!(d.kind, RuleKind::Deny);
        assert_eq!(d.text, "^zz$");
        assert_eq!(d.where_, RuleWhere::Host);
        assert!(d.ask);
        let p = &v.rules[1];
        assert_eq!(p.kind, RuleKind::DenyPath(RuleAccess::Write));
        assert_eq!(p.where_, RuleWhere::Everywhere);
        assert_eq!(p.reason, "p");
        assert_eq!(v.unenforced.len(), 1);
        assert_eq!(v.unenforced[0].source.line, 3);
        assert_eq!(v.unenforced[0].why, UnenforcedWhy::Judgement);
        assert!(view("not toml [").is_err());
    }

    fn rv(kind: RuleKind, where_: RuleWhere) -> UserRuleView {
        UserRuleView {
            id: None,
            kind,
            text: "x".into(),
            reason: "r".into(),
            where_,
            ask: false,
            source: None,
        }
    }

    #[test]
    fn box_status_per_kind() {
        use RuleWhere::*;
        assert_eq!(box_status(&rv(RuleKind::Deny, Host)), BoxStatus::OffInBoxes);
        assert_eq!(
            box_status(&rv(RuleKind::Deny, Everywhere)),
            BoxStatus::Advisory
        );
        for a in [
            RuleAccess::Write,
            RuleAccess::Any,
            RuleAccess::Replace,
            RuleAccess::Content,
        ] {
            assert_eq!(
                box_status(&rv(RuleKind::DenyPath(a), Everywhere)),
                BoxStatus::DiffReview
            );
        }
        assert_eq!(
            box_status(&rv(RuleKind::DenyPath(RuleAccess::Read), Everywhere)),
            BoxStatus::Advisory
        );
        assert_eq!(
            box_status(&rv(RuleKind::AllowPath(RuleAccess::Write), Everywhere)),
            BoxStatus::Advisory
        );
        assert_eq!(BoxStatus::OffInBoxes.label(), "off in boxes (host only)");
        assert_eq!(BoxStatus::DiffReview.label(), "checked at diff review");
        assert_eq!(BoxStatus::Advisory.label(), "advisory in boxes");
    }

    fn one(text: &str, profile: Profile) -> Vec<Pack> {
        load_user_packs(&[UserSrc { source: "t", text }], PathStyle::Posix, profile).unwrap()
    }

    const PATHS: &str = "[pack]\nid = \"user.t\"\n[[deny_path]]\nglob = \"**/.git/hooks/**\"\naccess = \"write\"\nreason = \"no hooks\"\n[[deny_path]]\nglob = \"$PROJECT/CLAUDE.md\"\naccess = \"write\"\nreason = \"no claude\"\n";

    #[test]
    #[cfg_attr(windows, ignore = "POSIX path examples")]
    fn diff_hits_flags_protected_paths() {
        let packs = one(PATHS, Profile::Box);
        let hits = diff_hits(
            &packs,
            Path::new("/repo"),
            Path::new("/home/u"),
            &["src/a.rs", ".git/hooks/pre-commit", "CLAUDE.md"],
        );
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].path, ".git/hooks/pre-commit");
        assert_eq!(hits[0].pack, "user.t");
        assert!(hits[0].reason.starts_with("no hooks"), "{}", hits[0].reason);
        assert_eq!(hits[1].path, "CLAUDE.md");
        assert_eq!(hits[1].pack, "user.t");
    }

    #[test]
    fn diff_hits_refuses_escaping_paths() {
        let packs = one(PATHS, Profile::Box);
        let hits = diff_hits(
            &packs,
            Path::new("/repo"),
            Path::new("/home/u"),
            &["../x", "/etc/passwd"],
        );
        assert_eq!(hits.len(), 2);
        for h in &hits {
            assert_eq!(h.pack, "saiife");
            assert_eq!(h.reason, "path leaves the repo");
        }
    }

    #[test]
    #[cfg_attr(windows, ignore = "POSIX path examples")]
    fn diff_hits_skips_host_rules() {
        let text = PATHS.replace("access = ", "where = \"host\"\naccess = ");
        let packs = one(&text, Profile::Box);
        let hits = diff_hits(
            &packs,
            Path::new("/repo"),
            Path::new("/home/u"),
            &[".git/hooks/pre-commit", "CLAUDE.md"],
        );
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    #[cfg_attr(windows, ignore = "POSIX path examples")]
    fn broad_findings_flag_the_hostile() {
        let broad = one(
            "[pack]\nid = \"user.b\"\ntriggers = [\"ls\"]\n[[deny]]\nid = \"d\"\npattern = '^\\S+'\nreason = \"r\"\n",
            Profile::Host,
        );
        let f = broad_findings(&broad[0]);
        assert_eq!(f[0].example, "ls");
        assert_eq!(f[0].rule, "^\\S+");
        let paths = one(
            "[pack]\nid = \"user.b\"\n[[deny_path]]\nglob = \"/**\"\nreason = \"r\"\n",
            Profile::Host,
        );
        let f = broad_findings(&paths[0]);
        assert!(
            f.iter()
                .any(|b| b.example == "/saiife-probe/project/src/main.rs"),
            "{f:?}"
        );
        let ok = one(
            "[pack]\nid = \"user.b\"\ntriggers = [\"pkill\"]\n[[deny]]\nid = \"d\"\npattern = '^pkill(?:\\s|$)'\nreason = \"r\"\n",
            Profile::Host,
        );
        assert!(broad_findings(&ok[0]).is_empty());
    }

    fn load_err(text: &str) -> String {
        load_user_packs(
            &[UserSrc {
                source: "t.toml",
                text,
            }],
            PathStyle::Posix,
            Profile::Host,
        )
        .map(|p| format!("loaded {} packs", p.len()))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "loaded".to_string())
    }

    #[test]
    fn unknown_top_level_key_is_an_error() {
        for table in ["[[deny_paths]]", "[[Deny]]"] {
            let text = format!("{A}{table}\nglob = \"$PROJECT/x\"\nreason = \"r\"\n");
            let e = load_err(&text);
            let key = table.trim_matches(|c| c == '[' || c == ']');
            assert!(
                e.contains("t.toml") && e.contains(&format!("unknown key {key:?}")),
                "{table}: {e}"
            );
        }
    }

    #[test]
    fn unknown_pack_key_is_an_error() {
        let text = A.replace(
            "triggers = [\"zz\"]",
            "triggers = [\"zz\"]\ntrigger = [\"zz\"]",
        );
        let e = load_err(&text);
        assert!(e.contains("unknown key \"trigger\" in [pack]"), "{e}");
    }

    #[test]
    fn command_rules_need_triggers() {
        let deny = A.replace("triggers = [\"zz\"]\n", "");
        let e = load_err(&deny);
        assert!(e.contains("needs triggers"), "{e}");
        let allow = "[pack]\nid = \"user.a\"\n[[allow]]\npattern = '^zz$'\nreason = \"r\"\n";
        assert!(load_err(allow).contains("needs triggers"));
        // Windows triggers do not count on a POSIX host ...
        let win = A.replace("triggers = ", "windows_triggers = ");
        assert!(load_err(&win).contains("needs triggers"));
        // ... but a rule for Windows only needs none there.
        let win_rule = win.replace("[[deny]]\n", "[[deny]]\nplatform = \"windows\"\n");
        assert_eq!(load_err(&win_rule), "loaded");
        // A pack of path rules only needs none.
        assert_eq!(load_err(PATHS), "loaded");
    }

    #[test]
    fn invalid_rule_id_is_an_error() {
        let e = load_err(&A.replace("id = \"d\"", "id = \"L3_1\""));
        assert!(e.contains("\"L3_1\"") && e.contains("rule id"), "{e}");
    }

    #[test]
    fn duplicate_rule_id_is_an_error() {
        let text = format!("{A}[[deny]]\nid = \"d\"\npattern = '^zz2$'\nreason = \"r\"\n");
        let e = load_err(&text);
        assert!(e.contains("\"d\"") && e.contains("used twice"), "{e}");
        let allow = format!(
            "{A}[[allow]]\nid = \"a\"\npattern = '^zz1$'\n[[allow]]\nid = \"a\"\npattern = '^zz2$'\n"
        );
        assert!(load_err(&allow).contains("used twice"));
    }

    #[test]
    fn lazy_is_an_error() {
        let e = load_err(&A.replace("triggers = ", "lazy = true\ntriggers = "));
        assert!(e.contains("cannot be lazy"), "{e}");
    }

    #[test]
    fn unjudged_path_is_a_diff_hit() {
        for trace in [
            AllowTrace::FailedOpenTimeout,
            AllowTrace::Unjudgeable { reason: "x".into() },
        ] {
            let h = diff_hit("a", Decision::Allow { trace }).unwrap();
            assert_eq!(h.path, "a");
            assert_eq!(h.pack, "saiife");
            assert_eq!(h.reason, "not judged");
        }
        assert!(diff_hit(
            "a",
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        )
        .is_none());
    }
}
