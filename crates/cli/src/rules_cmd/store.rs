//! Reading sources and writing the user pack (plan 33 task 5).
//!
//! A source is read as a regular file, never through a symlink (D6). The pack
//! is rendered with `toml_edit` from the same rule shapes the proposal was
//! verified with, and written through a temp file and a rename.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use saiifeguard::pack::RuleWhere;
use saiifeguard::userpack::valid_user_pack_id;
use sha2::{Digest, Sha256};
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table};

use super::extract::clean;
use super::propose::{access_word, pack_rules, rule_id, trigger, PackRule};
use super::{Choice, Decided, SourceLine, Unverified};

/// The largest source file read (D6).
pub const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

/// The longest file-name slug in a pack id (D6).
const SLUG_MAX: usize = 30;

/// The user packs of `t`: `policy.d/packs` beside the config it serves, the
/// directory plan 32's loaders read.
pub fn packs_dir(t: &crate::broker::Target) -> PathBuf {
    t.config()
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("policy.d")
        .join(saiife_policy::USER_PACKS_DIR)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `user.<slug>-<8 hex of SHA-256 of the absolute path>`, or `user.<name>`
/// for `--name` (D6). An id plan 32 would refuse is an error.
pub fn pack_id(abs_source: &Path, name: Option<&str>) -> Result<String, String> {
    let id = match name {
        Some(n) => format!("user.{n}"),
        None => {
            let file = abs_source
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let mut slug = String::new();
            for c in file.chars() {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    slug.push(c);
                } else if !slug.ends_with('-') {
                    slug.push('-');
                }
            }
            let slug: String = slug
                .trim_start_matches('-')
                .chars()
                .take(SLUG_MAX)
                .collect();
            let slug = match slug.trim_end_matches('-') {
                "" => "rules",
                s => s,
            };
            let digest = Sha256::digest(abs_source.as_os_str().as_encoded_bytes());
            format!("user.{slug}-{}", hex(&digest[..4]))
        }
    };
    if valid_user_pack_id(&id) {
        return Ok(id);
    }
    Err(match name {
        Some(n) => format!(
            "--name {}: use 1 to 48 of a-z, 0-9 or `-` (not first)",
            clean(n)
        ),
        None => format!(
            "no pack id for {}",
            clean(&abs_source.display().to_string())
        ),
    })
}

/// The source opened without following a symlink: a regular file, and as
/// root one with no other link (a link would read someone else's file).
#[cfg(unix)]
fn open_source(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => "it is a symlink: not followed".to_string(),
            _ => e.to_string(),
        })?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    if rustix::process::geteuid().is_root() && m.nlink() != 1 {
        return Err("has other links; not read as root".into());
    }
    Ok(f)
}

/// The source opened on the reparse point itself, never through it (a
/// symlink or junction is refused), as a regular file.
#[cfg(windows)]
fn open_source(path: &Path) -> Result<File, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("it is a reparse point (a symlink or junction): not followed".into());
    }
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    Ok(f)
}

/// The source's text (at most 1 MiB of UTF-8) and the hex SHA-256 of its bytes.
pub fn read_source(path: &Path) -> Result<(String, String), String> {
    let f = open_source(path)?;
    let mut bytes = Vec::new();
    f.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("larger than 1 MiB".into());
    }
    let sha = hex(&Sha256::digest(&bytes));
    let text = String::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_string())?;
    Ok((text, sha))
}

/// A pack to write: the confirmed decisions and what is not enforced.
#[derive(Debug, Clone)]
pub struct NewPack {
    pub id: String,
    /// The absolute source path.
    pub file: String,
    pub file_sha256: String,
    pub decided: Vec<Decided>,
    pub unverified: Vec<Unverified>,
    pub judgement: Vec<SourceLine>,
}

fn source_of(file: &str, s: &SourceLine) -> Item {
    let mut t = InlineTable::new();
    t.insert("file", file.into());
    t.insert("line", i64::from(s.line).into());
    t.insert("line_sha256", s.line_sha256.as_str().into());
    value(t)
}

/// A rule's common keys: `reason`, `source`, and `where` only when host.
fn common(t: &mut Table, reason: &str, file: &str, d: &Decided) {
    t["reason"] = value(reason);
    t["source"] = source_of(file, &d.p.src);
    if d.where_ == RuleWhere::Host {
        t["where"] = value("host");
    }
}

/// The rule tables a set of decisions becomes.
#[derive(Default)]
pub(crate) struct RuleTables {
    pub deny: ArrayOfTables,
    pub allow: ArrayOfTables,
    pub deny_path: ArrayOfTables,
}

/// An `[[unenforced]]` entry; `why` is `skipped`, `unverified` or `judgement`.
pub(crate) fn unenforced_table(file: &str, s: &SourceLine, why: &str) -> Table {
    let mut t = Table::new();
    t["source"] = source_of(file, s);
    t["text"] = value(clean(&s.text));
    t["why"] = value(why);
    t
}

/// The rule tables of one enforced decision, from the shared `pack_rules`
/// enumeration (import and sync both render through this). `next_id` gives
/// the id of each `[[deny]]` of the given source line.
pub(crate) fn push_decided(
    out: &mut RuleTables,
    file: &str,
    d: &Decided,
    next_id: &mut dyn FnMut(u32) -> String,
) {
    for r in pack_rules(&d.p) {
        let mut t = Table::new();
        match r {
            PackRule::Deny(c) => {
                t["id"] = value(next_id(d.p.src.line));
                t["pattern"] = value(&c.pattern);
                common(&mut t, &d.p.reason, file, d);
                if d.choice == Choice::Ask {
                    t["ask"] = value(true);
                }
                if c.whole_segment {
                    t["whole_segment"] = value(true);
                }
                if c.peeled_wrappers {
                    t["peeled_wrappers"] = value(true);
                }
                out.deny.push(t);
            }
            PackRule::HelpAllow { pattern, reason } => {
                t["pattern"] = value(pattern);
                common(&mut t, &reason, file, d);
                t["whole_segment"] = value(true);
                out.allow.push(t);
            }
            PackRule::DenyPath { glob, access } => {
                t["glob"] = value(glob);
                t["access"] = value(access_word(access));
                common(&mut t, &d.p.reason, file, d);
                out.deny_path.push(t);
            }
        }
    }
}

/// The pack text: `[pack]`, `[import]`, the confirmed rules and an
/// `[[unenforced]]` entry per skipped, unverified or judgement line.
pub fn render(p: &NewPack) -> String {
    let file_name = Path::new(&p.file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.file.clone());
    let enforced: Vec<&Decided> = p
        .decided
        .iter()
        .filter(|d| d.choice != Choice::Skip)
        .collect();
    let mut triggers: Vec<&str> = enforced.iter().filter_map(|d| trigger(&d.p)).collect();
    triggers.sort_unstable();
    triggers.dedup();

    let mut doc = DocumentMut::new();
    let mut pack = Table::new();
    pack["id"] = value(&p.id);
    pack["name"] = value(format!("Never-rules from {file_name}"));
    pack["description"] = value("saiife rules import; change with saiife rules sync");
    pack["version"] = value(1);
    pack["triggers"] = value(triggers.into_iter().collect::<Array>());
    doc["pack"] = Item::Table(pack);
    let mut import = Table::new();
    import["file"] = value(&p.file);
    import["sha256"] = value(&p.file_sha256);
    doc["import"] = Item::Table(import);

    let mut tables = RuleTables::default();
    // The next `k` of each line's `l<line>-<k>` ids.
    let mut used: BTreeMap<u32, usize> = BTreeMap::new();
    for d in enforced {
        push_decided(&mut tables, &p.file, d, &mut |line| {
            let k = used.entry(line).or_insert(0);
            *k += 1;
            rule_id(line, *k)
        });
    }
    let RuleTables {
        deny,
        allow,
        deny_path,
    } = tables;

    // One entry per line and why, in line order.
    let mut unenforced: Vec<(&SourceLine, &str)> = Vec::new();
    for d in p.decided.iter().filter(|d| d.choice == Choice::Skip) {
        unenforced.push((&d.p.src, "skipped"));
    }
    for u in &p.unverified {
        unenforced.push((&u.src, "unverified"));
    }
    for j in &p.judgement {
        unenforced.push((j, "judgement"));
    }
    unenforced.sort_by_key(|(s, _)| s.line);
    unenforced.dedup_by(|a, b| a.0.line == b.0.line && a.1 == b.1);
    let mut un = ArrayOfTables::new();
    for (s, why) in unenforced {
        un.push(unenforced_table(&p.file, s, why));
    }

    for (key, aot) in [
        ("deny", deny),
        ("allow", allow),
        ("deny_path", deny_path),
        ("unenforced", un),
    ] {
        if !aot.is_empty() {
            doc[key] = Item::ArrayOfTables(aot);
        }
    }
    doc.to_string()
}

/// `dir` (or, when it is missing, its nearest existing parent) must be
/// writable before the human answers anything.
pub fn check_writable(dir: &Path) -> Result<(), String> {
    let probe = dir
        .ancestors()
        .find(|d| d.is_dir())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    return rustix::fs::access(probe, rustix::fs::Access::WRITE_OK)
        .map_err(|e| format!("cannot write to {}: {e}", probe.display()));
    // Windows answers by the ACL at the write itself.
    #[cfg(not(unix))]
    std::fs::metadata(probe)
        .map(|_| ())
        .map_err(|e| format!("cannot write to {}: {e}", probe.display()))
}

fn make_dir(dir: &Path, locked: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(if locked { 0o755 } else { 0o700 })
            .create(dir)
    }
    // New entries inherit the ACL above them (root's on a locked host).
    #[cfg(not(unix))]
    {
        let _ = locked;
        std::fs::create_dir_all(dir)
    }
}

fn create_tmp(tmp: &Path, locked: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = if locked { 0o644 } else { 0o600 };
        o.mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let f = o.open(tmp)?;
        // The umask may have taken bits away: the mode is exact.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        let _ = locked;
        o.open(tmp)
    }
}

/// `<dir>/<id>.toml`, new, through `<dir>/.<id>.toml.tmp` (fsynced, then
/// renamed). The dir is made 0755 (locked) or 0700, the file 0644 or 0600.
pub fn write_pack(dir: &Path, id: &str, text: &str, locked: bool) -> Result<PathBuf, String> {
    let shown = |p: &Path| clean(&p.display().to_string());
    make_dir(dir, locked).map_err(|e| format!("cannot make {}: {e}", shown(dir)))?;
    let target = dir.join(format!("{id}.toml"));
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(format!("{} exists; use saiife rules sync", shown(&target)));
    }
    let tmp = dir.join(format!(".{id}.toml.tmp"));
    // A temp file left by a run that died is ours to replace (the name
    // starts with a dot, so no loader reads it).
    if std::fs::symlink_metadata(&tmp).is_ok() {
        std::fs::remove_file(&tmp).map_err(|e| format!("cannot remove {}: {e}", shown(&tmp)))?;
    }
    let wrote = create_tmp(&tmp, locked).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        f.sync_all()
    });
    let done = wrote.and_then(|()| std::fs::rename(&tmp, &target));
    if let Err(e) = done {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", shown(&target)));
    }
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(target)
}

/// Replaces the pack file `path` with `text`: a temp file beside it
/// (`O_EXCL`, `O_NOFOLLOW`, mode 0644 locked or 0600), fsynced, renamed over.
pub fn replace_pack(path: &Path, text: &str, locked: bool) -> Result<(), String> {
    let shown = |p: &Path| clean(&p.display().to_string());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp"));
    if std::fs::symlink_metadata(&tmp).is_ok() {
        std::fs::remove_file(&tmp).map_err(|e| format!("cannot remove {}: {e}", shown(&tmp)))?;
    }
    let wrote = create_tmp(&tmp, locked).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        f.sync_all()
    });
    let done = wrote.and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = done {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", shown(path)));
    }
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_cmd::extract::line_sha256;
    use crate::rules_cmd::propose::{propose, verify};
    use crate::rules_cmd::{Candidate, Choice, Origin, Target};
    use saiifeguard::canon::{PathStyle, PathVars};
    use saiifeguard::pack::RuleWhere;
    use saiifeguard::pathrule::RuleAccess;
    use saiifeguard::profile::Profile;
    use saiifeguard::userpack::{load_user_packs, view, RuleKind, UnenforcedWhy, UserSrc};

    fn vars() -> PathVars {
        PathVars::new()
            .with_cwd("/saiife-test/project")
            .with_var("PROJECT", "/saiife-test/project")
            .with_var("HOME", "/saiife-test/home")
    }

    fn src(line: u32, text: &str) -> SourceLine {
        SourceLine {
            line,
            line_sha256: line_sha256(text),
            text: text.to_string(),
        }
    }

    fn decided(s: &SourceLine, t: Target, choice: Choice, where_: RuleWhere) -> Decided {
        let c = Candidate {
            src: s.clone(),
            targets: vec![t],
        };
        let mut p = propose(&c, "CLAUDE.md", Origin::Rules).remove(0);
        verify(&mut p, &vars()).unwrap();
        Decided { p, choice, where_ }
    }

    fn cmd(w: &[&str]) -> Target {
        Target::Command(w.iter().map(|s| (*s).to_string()).collect())
    }

    const FILE: &str = "/saiife-test/project/CLAUDE.md";

    #[test]
    fn render_round_trips_through_view() {
        let l1 = src(1, "- Never run `deploy-prod`.");
        let l2 = src(2, "- Never run `terraform apply`.");
        let l3 = src(3, "- Never write to /etc/hosts.");
        let l4 = src(4, "- Never run `pkill`.");
        let l5 = src(5, "- Never be rude.");
        let pack = NewPack {
            id: "user.claude-md-1a2b3c4d".into(),
            file: FILE.into(),
            file_sha256: "ab".repeat(32),
            decided: vec![
                decided(
                    &l1,
                    cmd(&["deploy-prod"]),
                    Choice::Enforce,
                    RuleWhere::Everywhere,
                ),
                decided(
                    &l2,
                    cmd(&["terraform", "apply"]),
                    Choice::Ask,
                    RuleWhere::Everywhere,
                ),
                decided(
                    &l3,
                    Target::Path {
                        glob: "/etc/hosts".into(),
                        access: RuleAccess::Write,
                    },
                    Choice::Enforce,
                    RuleWhere::Host,
                ),
                decided(&l4, cmd(&["pkill"]), Choice::Skip, RuleWhere::Everywhere),
            ],
            unverified: vec![],
            judgement: vec![l5.clone()],
        };
        let text = render(&pack);
        let v = view(&text).unwrap();
        assert_eq!(v.id, "user.claude-md-1a2b3c4d");
        assert_eq!(v.name, "Never-rules from CLAUDE.md");
        let imp = v.import.as_ref().unwrap();
        assert_eq!(imp.file, FILE);
        assert_eq!(imp.sha256, "ab".repeat(32));

        let deny: Vec<_> = v
            .rules
            .iter()
            .filter(|r| r.kind == RuleKind::Deny)
            .collect();
        assert_eq!(deny.len(), 2, "{text}");
        assert_eq!(deny[0].id.as_deref(), Some("l1-1"));
        assert_eq!(deny[0].where_, RuleWhere::Everywhere);
        assert!(!deny[0].ask);
        let s = deny[0].source.as_ref().unwrap();
        assert_eq!((s.file.as_str(), s.line), (FILE, 1));
        assert_eq!(s.line_sha256, l1.line_sha256);
        assert_eq!(deny[0].reason, "CLAUDE.md:1 \"Never run `deploy-prod`.\"");
        assert_eq!(deny[1].id.as_deref(), Some("l2-1"));
        assert!(deny[1].ask);
        // `where` is written only when the human chose host.
        assert!(!text.contains("where = \"everywhere\""), "{text}");

        let allow: Vec<_> = v
            .rules
            .iter()
            .filter(|r| r.kind == RuleKind::Allow)
            .collect();
        assert_eq!(allow.len(), 1, "{text}");
        assert_eq!(allow[0].reason, "deploy-prod --help changes nothing");
        assert_eq!(allow[0].source.as_ref().unwrap().line, 1);

        let paths: Vec<_> = v
            .rules
            .iter()
            .filter(|r| matches!(r.kind, RuleKind::DenyPath(RuleAccess::Write)))
            .collect();
        assert_eq!(paths.len(), 2, "{text}");
        assert!(paths.iter().all(|r| r.where_ == RuleWhere::Host));
        assert_eq!(paths[0].text, "/etc/hosts");
        assert_eq!(paths[1].text, "/etc/hosts/**");
        assert_eq!(paths[0].source.as_ref().unwrap().line, 3);

        assert_eq!(v.unenforced.len(), 2, "{text}");
        assert_eq!(v.unenforced[0].why, UnenforcedWhy::Skipped);
        assert_eq!(v.unenforced[0].source.line, 4);
        assert_eq!(v.unenforced[0].text, l4.text);
        assert_eq!(v.unenforced[1].why, UnenforcedWhy::Judgement);
        assert_eq!(v.unenforced[1].source.line_sha256, l5.line_sha256);

        assert!(
            text.contains("triggers = [\"deploy-prod\", \"terraform\"]"),
            "{text}"
        );
        for profile in [Profile::Host, Profile::Box] {
            load_user_packs(
                &[UserSrc {
                    source: "new",
                    text: &text,
                }],
                PathStyle::host(),
                profile,
            )
            .unwrap();
        }
    }

    #[test]
    fn render_matches_the_verified_pack_shape() {
        // The ids and the carve-out are those `one_rule_pack` verified.
        let l = src(9, "- Never run `sudo`.");
        let d = decided(&l, cmd(&["sudo"]), Choice::Enforce, RuleWhere::Everywhere);
        let pack = NewPack {
            id: "user.t".into(),
            file: FILE.into(),
            file_sha256: "00".repeat(32),
            decided: vec![d],
            unverified: vec![Unverified {
                src: src(10, "- Never run `x\u{1b}`."),
                why: "bad".into(),
            }],
            judgement: vec![],
        };
        let v = view(&render(&pack)).unwrap();
        let ids: Vec<_> = v.rules.iter().filter_map(|r| r.id.clone()).collect();
        assert_eq!(ids, ["l9-1", "l9-2"]);
        assert_eq!(v.unenforced.len(), 1);
        assert_eq!(v.unenforced[0].why, UnenforcedWhy::Unverified);
        // The text is stored cleaned; the hash is of the line as written.
        assert_eq!(v.unenforced[0].text, "- Never run `x?`.");
        assert_eq!(
            v.unenforced[0].source.line_sha256,
            line_sha256("- Never run `x\u{1b}`.")
        );
    }

    #[test]
    fn two_proposals_on_one_line_take_the_next_ids() {
        let l = src(4, "- Never run `foo` or `bar`.");
        let pack = NewPack {
            id: "user.t".into(),
            file: FILE.into(),
            file_sha256: "00".repeat(32),
            decided: vec![
                decided(&l, cmd(&["foo"]), Choice::Enforce, RuleWhere::Everywhere),
                decided(&l, cmd(&["bar"]), Choice::Enforce, RuleWhere::Everywhere),
            ],
            unverified: vec![],
            judgement: vec![],
        };
        let text = render(&pack);
        let v = view(&text).unwrap();
        let ids: Vec<_> = v.rules.iter().filter_map(|r| r.id.clone()).collect();
        assert_eq!(ids, ["l4-1", "l4-2"]);
        load_user_packs(
            &[UserSrc {
                source: "new",
                text: &text,
            }],
            PathStyle::host(),
            Profile::Host,
        )
        .unwrap();
    }

    /// The rendered pack of one line, enforced or skipped, with the
    /// built-in packs before it, as the hook judges.
    fn engine_for(line: &str, w: &str, choice: Choice) -> saiifeguard::engine::Engine {
        let l = src(1, line);
        let pack = NewPack {
            id: "user.t".into(),
            file: FILE.into(),
            file_sha256: "00".repeat(32),
            decided: vec![decided(&l, cmd(&[w]), choice, RuleWhere::Everywhere)],
            unverified: vec![],
            judgement: vec![],
        };
        let text = render(&pack);
        let (mut packs, _) = saiifeguard::builtins::builtin_packs();
        if choice != Choice::Skip {
            packs.extend(
                load_user_packs(
                    &[UserSrc {
                        source: "new",
                        text: &text,
                    }],
                    PathStyle::host(),
                    Profile::Host,
                )
                .unwrap(),
            );
        } else {
            assert!(!text.contains("[[allow]]"), "{text}");
        }
        saiifeguard::engine::Engine::new(packs).with_paths(vars())
    }

    fn denied_by(e: &saiifeguard::engine::Engine, c: &str) -> Option<String> {
        match e.evaluate(c) {
            saiifeguard::Decision::Deny { pack, .. } => Some(pack),
            saiifeguard::Decision::Allow { .. } => None,
        }
    }

    #[test]
    fn carve_out_never_lifts_another_packs_deny() {
        // `mkfs` is denied by core.filesystem whatever follows: the import's
        // `mkfs --help` carve-out lifts only its own pack's deny.
        let e = engine_for("Never run `mkfs`.", "mkfs", Choice::Enforce);
        assert_eq!(
            denied_by(&e, "mkfs --help").as_deref(),
            Some("core.filesystem")
        );
        assert_eq!(
            denied_by(&e, "mkfs.ext4 /dev/sda").as_deref(),
            Some("core.filesystem")
        );
    }

    #[test]
    fn shutdown_dash_h_is_never_carved_out() {
        let e = engine_for("Never run `shutdown`.", "shutdown", Choice::Enforce);
        assert_eq!(denied_by(&e, "shutdown -h now").as_deref(), Some("user.t"));
        assert_eq!(denied_by(&e, "shutdown -h").as_deref(), Some("user.t"));
        assert_eq!(denied_by(&e, "shutdown now").as_deref(), Some("user.t"));
        // The confirmed rule's shown carve-out lets help through ...
        assert_eq!(denied_by(&e, "shutdown --help"), None);
        assert_eq!(denied_by(&e, "shutdown --version"), None);
        // ... and only it: the same deny without its [[allow]] blocks help.
        let l = src(1, "Never run `shutdown`.");
        let text = render(&NewPack {
            id: "user.t".into(),
            file: FILE.into(),
            file_sha256: "00".repeat(32),
            decided: vec![decided(
                &l,
                cmd(&["shutdown"]),
                Choice::Enforce,
                RuleWhere::Everywhere,
            )],
            unverified: vec![],
            judgement: vec![],
        });
        let cut = text.split("[[allow]]").next().unwrap().to_string();
        let packs = load_user_packs(
            &[UserSrc {
                source: "cut",
                text: &cut,
            }],
            PathStyle::host(),
            Profile::Host,
        )
        .unwrap();
        let bare = saiifeguard::engine::Engine::new(packs).with_paths(vars());
        assert_eq!(
            denied_by(&bare, "shutdown --help").as_deref(),
            Some("user.t")
        );
        // A skipped rule writes no carve-out (and no deny).
        let skipped = engine_for("Never run `shutdown`.", "shutdown", Choice::Skip);
        assert_eq!(denied_by(&skipped, "shutdown -h now"), None);
    }

    #[test]
    fn pack_id_shape() {
        let a = pack_id(Path::new("/p/CLAUDE.md"), None).unwrap();
        let rest = a.strip_prefix("user.claude-md-").unwrap();
        assert_eq!(rest.len(), 8);
        assert!(rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(pack_id(Path::new("/p/CLAUDE.md"), None).unwrap(), a);
        assert_ne!(pack_id(Path::new("/q/CLAUDE.md"), None).unwrap(), a);
        assert!(pack_id(Path::new("/p/CLAUDE.md"), Some("Bad_Name")).is_err());
        assert_eq!(
            pack_id(Path::new("/p/CLAUDE.md"), Some("no-prod")).unwrap(),
            "user.no-prod"
        );
        // A leading dot and a long name still give a valid id.
        let d = pack_id(Path::new("/p/.cursorrules"), None).unwrap();
        assert!(saiifeguard::userpack::valid_user_pack_id(&d), "{d}");
        let long = pack_id(Path::new(&format!("/p/{}.md", "A".repeat(80))), None).unwrap();
        assert!(saiifeguard::userpack::valid_user_pack_id(&long), "{long}");
    }

    #[cfg(unix)]
    #[test]
    fn write_pack_is_new_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("policy.d/packs");
        let p = write_pack(&dir, "user.t", "x = 1\n", false).unwrap();
        assert_eq!(p, dir.join("user.t.toml"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "x = 1\n");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert!(!dir.join(".user.t.toml.tmp").exists());
        let e = write_pack(&dir, "user.t", "y = 1\n", false).unwrap_err();
        assert!(e.contains("exists; use saiife rules sync"), "{e}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "x = 1\n");
        let q = write_pack(&tmp.path().join("locked"), "user.u", "z = 1\n", true).unwrap();
        assert_eq!(mode(&q), 0o644);
        assert_eq!(mode(&tmp.path().join("locked")), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn read_source_checks_and_hashes() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("CLAUDE.md");
        std::fs::write(&f, "Never run `x`.\n").unwrap();
        let (text, sha) = read_source(&f).unwrap();
        assert_eq!(text, "Never run `x`.\n");
        assert_eq!(sha.len(), 64);
        let link = tmp.path().join("AGENTS.md");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(read_source(&link).unwrap_err().contains("symlink"));
        let big = tmp.path().join("big.md");
        std::fs::write(&big, vec![b'a'; 1024 * 1024 + 1]).unwrap();
        assert!(read_source(&big).unwrap_err().contains("1 MiB"));
        let bad = tmp.path().join("bad.md");
        std::fs::write(&bad, [0xff, 0xfe]).unwrap();
        assert!(read_source(&bad).unwrap_err().contains("UTF-8"));
        assert!(read_source(tmp.path()).is_err());
    }
}
