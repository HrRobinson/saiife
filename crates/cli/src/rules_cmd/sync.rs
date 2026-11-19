//! Follow edits to imported files (plan 33 task 6, D7).
//!
//! `plan` compares a pack's source references with the file's current text;
//! `apply` edits the pack with `toml_edit`, keeping every key and comment it
//! does not change.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use saiifeguard::userpack::{RuleKind, SourceRef, UnenforcedWhy, UserPackView};
use sha2::Digest as _;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, TableLike, Value};

use super::extract::{all_lines, candidates};
use super::propose::trigger;
use super::store::{hex, push_decided, unenforced_table, RuleTables};
use super::{Candidate, Choice, Decided, SourceLine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPlan {
    /// `(line_sha256, from, to)`: the line is still in the file, elsewhere.
    pub moved: Vec<(String, u32, u32)>,
    /// A source line no longer in the file: its reference, text and the
    /// number of rules (carve-outs not counted) it carries.
    pub gone: Vec<(SourceRef, String, usize)>,
    /// Never-lines the pack knows nothing about.
    pub new: Vec<Candidate>,
    pub file_sha256: String,
}

/// What a rule's `reason` quotes: the text between its first and last `"`.
fn quoted(reason: &str) -> Option<&str> {
    let a = reason.find('"')?;
    let b = reason.rfind('"')?;
    (b > a).then(|| &reason[a + 1..b])
}

pub fn plan(view: &UserPackView, text: &str) -> SyncPlan {
    let lines = all_lines(text);
    // Every (hash, line) the pack holds, in pack order.
    let mut refs: Vec<(&SourceRef, Option<&str>, bool)> = Vec::new();
    for r in &view.rules {
        if let Some(s) = &r.source {
            let counts = !matches!(r.kind, RuleKind::Allow | RuleKind::AllowPath(_));
            refs.push((s, quoted(&r.reason), counts));
        }
    }
    for u in &view.unenforced {
        refs.push((&u.source, Some(u.text.as_str()), false));
    }
    let known: HashSet<&str> = refs
        .iter()
        .map(|(s, _, _)| s.line_sha256.as_str())
        .collect();

    let mut moved: Vec<(String, u32, u32)> = Vec::new();
    let mut gone: Vec<(SourceRef, String, usize)> = Vec::new();
    let mut seen: BTreeSet<(&str, u32)> = BTreeSet::new();
    for (s, _, _) in &refs {
        let h = s.line_sha256.as_str();
        if !seen.insert((h, s.line)) {
            continue;
        }
        let at: Vec<u32> = lines
            .iter()
            .filter(|l| l.line_sha256 == h)
            .map(|l| l.line)
            .collect();
        if at.is_empty() {
            if gone.iter().any(|(g, _, _)| g.line_sha256 == h) {
                continue;
            }
            let group = || refs.iter().filter(|(r, _, _)| r.line_sha256 == h);
            let text = group()
                .filter_map(|(_, t, _)| *t)
                .next()
                .unwrap_or_default()
                .to_string();
            let rules = group().filter(|(_, _, c)| *c).count();
            gone.push(((*s).clone(), text, rules));
        } else if !at.contains(&s.line) {
            let to = *at
                .iter()
                .min_by_key(|l| l.abs_diff(s.line))
                .unwrap_or(&s.line);
            moved.push((h.to_string(), s.line, to));
        }
    }
    let new = candidates(text)
        .into_iter()
        .filter(|c| !known.contains(c.src.line_sha256.as_str()))
        .collect();
    SyncPlan {
        moved,
        gone,
        new,
        file_sha256: hex(&sha2::Sha256::digest(text.as_bytes())),
    }
}

fn hash_of(t: &dyn TableLike) -> Option<String> {
    t.get("source")?
        .as_table_like()?
        .get("line_sha256")?
        .as_str()
        .map(str::to_string)
}

fn line_of(t: &dyn TableLike) -> Option<i64> {
    t.get("source")?.as_table_like()?.get("line")?.as_integer()
}

/// Sets `source.line`, keeping the value's spacing.
fn set_line(t: &mut dyn TableLike, line: u32) {
    let Some(src) = t.get_mut("source").and_then(Item::as_table_like_mut) else {
        return;
    };
    match src.get_mut("line").and_then(Item::as_value_mut) {
        Some(v) => {
            let decor = v.decor().clone();
            *v = Value::from(i64::from(line));
            *v.decor_mut() = decor;
        }
        None => {
            src.insert("line", value(i64::from(line)));
        }
    }
}

const RULE_KEYS: [&str; 4] = ["allow", "deny", "allow_path", "deny_path"];

fn aot<'a>(doc: &'a mut DocumentMut, key: &str) -> Result<Option<&'a mut ArrayOfTables>, String> {
    match doc.get_mut(key) {
        None => Ok(None),
        Some(Item::ArrayOfTables(a)) => Ok(Some(a)),
        Some(_) => Err(format!("[[{key}]] is not written as a table array")),
    }
}

fn append(doc: &mut DocumentMut, key: &str, add: ArrayOfTables) -> Result<(), String> {
    if add.is_empty() {
        return Ok(());
    }
    match aot(doc, key)? {
        Some(a) => {
            for t in add {
                a.push(t);
            }
        }
        None => doc[key] = Item::ArrayOfTables(add),
    }
    Ok(())
}

/// `pack_text` with the sync applied: moved references renumbered, the rules
/// of `removed` lines (and every gone `[[unenforced]]`) dropped, the new
/// rules and entries appended, `[import] sha256` set. Everything else is
/// kept as written.
pub fn apply(
    pack_text: &str,
    plan: &SyncPlan,
    removed: &[String],
    added: &[Decided],
    unenforced: &[(SourceLine, UnenforcedWhy)],
) -> Result<String, String> {
    let mut doc: DocumentMut = pack_text.parse().map_err(|e| format!("pack: {e}"))?;
    let file = doc
        .get("import")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("file"))
        .and_then(Item::as_str)
        .ok_or("pack has no [import] file")?
        .to_string();
    let moves: BTreeMap<(&str, u32), u32> = plan
        .moved
        .iter()
        .map(|(h, from, to)| ((h.as_str(), *from), *to))
        .collect();
    let gone: HashSet<&str> = plan
        .gone
        .iter()
        .map(|(s, _, _)| s.line_sha256.as_str())
        .collect();
    let removed: HashSet<&str> = removed.iter().map(String::as_str).collect();

    // Triggers are never pruned: a kept rule may need a word its pattern
    // does not start with, and a stale trigger only costs a little speed.
    for key in RULE_KEYS.into_iter().chain(["unenforced"]) {
        let Some(a) = aot(&mut doc, key)? else {
            continue;
        };
        if key == "unenforced" {
            a.retain(|t| hash_of(t).is_none_or(|h| !gone.contains(h.as_str())));
        } else {
            a.retain(|t| hash_of(t).is_none_or(|h| !removed.contains(h.as_str())));
        }
        for t in a.iter_mut() {
            if let (Some(h), Some(l)) = (hash_of(t), line_of(t)) {
                if let Some(to) = u32::try_from(l)
                    .ok()
                    .and_then(|l| moves.get(&(h.as_str(), l)))
                {
                    set_line(t, *to);
                }
            }
        }
        if a.is_empty() {
            doc.remove(key);
        }
    }

    // New rules take the first free ids; the pack's triggers learn the new
    // command words.
    let mut ids: HashSet<String> = HashSet::new();
    if let Some(a) = aot(&mut doc, "deny")? {
        ids.extend(
            a.iter()
                .filter_map(|t| t.get("id")?.as_str().map(str::to_string)),
        );
    }
    let enforced: Vec<&Decided> = added.iter().filter(|d| d.choice != Choice::Skip).collect();
    let mut tables = RuleTables::default();
    for d in &enforced {
        push_decided(&mut tables, &file, d, &mut |line| {
            let mut k = 1;
            loop {
                let id = super::propose::rule_id(line, k);
                if ids.insert(id.clone()) {
                    return id;
                }
                k += 1;
            }
        });
    }
    let RuleTables {
        deny,
        allow,
        deny_path,
    } = tables;
    append(&mut doc, "deny", deny)?;
    append(&mut doc, "allow", allow)?;
    append(&mut doc, "deny_path", deny_path)?;
    if let Some(tr) = doc
        .get_mut("pack")
        .and_then(Item::as_table_like_mut)
        .and_then(|p| p.get_mut("triggers"))
        .and_then(Item::as_array_mut)
    {
        for w in enforced.iter().filter_map(|d| trigger(&d.p)) {
            if !tr.iter().any(|v| v.as_str() == Some(w)) {
                tr.push(w);
            }
        }
    }
    let mut un = ArrayOfTables::new();
    for d in added.iter().filter(|d| d.choice == Choice::Skip) {
        un.push(unenforced_table(&file, &d.p.src, "skipped"));
    }
    for (s, why) in unenforced {
        let w = match why {
            UnenforcedWhy::Judgement => "judgement",
            UnenforcedWhy::Skipped => "skipped",
            UnenforcedWhy::Unverified => "unverified",
        };
        un.push(unenforced_table(&file, s, w));
    }
    append(&mut doc, "unenforced", un)?;

    let import = doc
        .get_mut("import")
        .and_then(Item::as_table_like_mut)
        .ok_or("pack has no [import]")?;
    match import.get_mut("sha256").and_then(Item::as_value_mut) {
        Some(v) => {
            let decor = v.decor().clone();
            *v = Value::from(plan.file_sha256.as_str());
            *v.decor_mut() = decor;
        }
        None => {
            import.insert("sha256", value(plan.file_sha256.as_str()));
        }
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_cmd::extract::line_sha256;
    use crate::rules_cmd::propose::{propose, verify};
    use crate::rules_cmd::store::{render, NewPack};
    use crate::rules_cmd::{Origin, Target};
    use saiifeguard::pack::RuleWhere;
    use saiifeguard::userpack::view;

    const FILE: &str = "/saiife-test/project/CLAUDE.md";

    use crate::rules_cmd::test_host::vars;

    fn src(line: u32, text: &str) -> SourceLine {
        SourceLine {
            line,
            line_sha256: line_sha256(text),
            text: text.to_string(),
        }
    }

    fn decided(s: &SourceLine, w: &[&str], choice: Choice) -> Decided {
        let c = Candidate {
            src: s.clone(),
            targets: vec![Target::Command(
                w.iter().map(|x| (*x).to_string()).collect(),
            )],
        };
        let mut p = propose(&c, "CLAUDE.md", Origin::Rules).remove(0);
        verify(&mut p, &vars()).unwrap();
        Decided {
            p,
            choice,
            where_: RuleWhere::Everywhere,
        }
    }

    fn pack_of(text: &str, rules: &[(&str, &str)]) -> String {
        let lines = all_lines(text);
        let decided = rules
            .iter()
            .map(|(line, w)| {
                let l = lines.iter().find(|l| l.text == *line).unwrap();
                decided(l, &[w], Choice::Enforce)
            })
            .collect();
        render(&NewPack {
            id: "user.claude-md-test".into(),
            file: FILE.into(),
            file_sha256: "00".into(),
            decided,
            unverified: vec![],
            judgement: vec![],
        })
    }

    #[test]
    fn moved_line_keeps_rule() {
        let pack = pack_of("a\nNever run `x1`.", &[("Never run `x1`.", "x1")]);
        let v = view(&pack).unwrap();
        let p = plan(&v, "intro\na\nNever run `x1`.");
        let h = line_sha256("Never run `x1`.");
        assert_eq!(p.moved, vec![(h, 2, 3)]);
        assert!(p.gone.is_empty() && p.new.is_empty());
        let out = apply(&pack, &p, &[], &[], &[]).unwrap();
        let v2 = view(&out).unwrap();
        assert!(v2
            .rules
            .iter()
            .all(|r| r.source.as_ref().unwrap().line == 3));
        assert!(out.contains("id = \"l2-1\""), "{out}");
        assert!(out.contains(&p.file_sha256));
    }

    #[test]
    fn apply_keeps_hand_edits() {
        let pack = pack_of("Never run `x1`.", &[("Never run `x1`.", "x1")]);
        let pack = format!("# my note\n{pack}").replacen(
            "[[deny]]\n",
            "[[deny]]\noperand_min_len = 2\n",
            1,
        );
        let v = view(&pack).unwrap();
        let p = plan(&v, "\nNever run `x1`.");
        let out = apply(&pack, &p, &[], &[], &[]).unwrap();
        assert!(out.starts_with("# my note\n"), "{out}");
        assert!(out.contains("operand_min_len = 2"), "{out}");
        assert!(out.contains("line = 2"), "{out}");
    }

    #[test]
    fn gone_line_is_listed_with_its_rule_count() {
        let pack = pack_of("Never run `x1`.", &[("Never run `x1`.", "x1")]);
        let p = plan(&view(&pack).unwrap(), "nothing here\n");
        assert_eq!(p.gone.len(), 1);
        assert_eq!(p.gone[0].1, "Never run `x1`.");
        assert!(p.gone[0].2 >= 1);
        let h = line_sha256("Never run `x1`.");
        let out = apply(&pack, &p, &[h], &[], &[]).unwrap();
        assert!(view(&out).unwrap().rules.is_empty(), "{out}");
    }

    #[test]
    fn kept_hand_edited_rule_keeps_its_trigger_and_still_denies() {
        let md = "Never run `rm`.\nNever run `ls`.\n";
        let pack = pack_of(md, &[("Never run `rm`.", "rm"), ("Never run `ls`.", "ls")]);
        // Hand edit: the ls rule now also covers `rm` behind sudo, written
        // so that it does not start with `^rm`.
        let pack = pack.replacen(
            "pattern = '^ls(?:\\s|$)'",
            "pattern = '(?:sudo\\s+)?rm\\b'",
            1,
        );
        assert!(pack.contains("(?:sudo\\s+)?rm\\b"), "{pack}");
        let rm_hash = line_sha256("Never run `rm`.");
        let p = plan(&view(&pack).unwrap(), "Never run `ls`.\n");
        let out = apply(&pack, &p, &[rm_hash], &[], &[]).unwrap();
        let triggers = out.lines().find(|l| l.starts_with("triggers")).unwrap();
        assert!(triggers.contains("\"rm\""), "{triggers}");
        let srcs = [saiifeguard::userpack::UserSrc {
            source: "user.claude-md-test.toml",
            text: &out,
        }];
        let packs = saiifeguard::userpack::load_user_packs(
            &srcs,
            saiifeguard::canon::PathStyle::host(),
            saiifeguard::profile::Profile::Host,
        )
        .unwrap();
        let e = saiifeguard::engine::Engine::new(packs).with_paths(vars());
        for cmd in ["rm x", "sudo rm x"] {
            assert!(
                matches!(e.evaluate(cmd), saiifeguard::engine::Decision::Deny { .. }),
                "{cmd}: {out}"
            );
        }
    }

    #[test]
    fn added_rule_takes_the_first_free_id() {
        let pack = pack_of("Never run `x1`.", &[("Never run `x1`.", "x1")]);
        let l = src(1, "Never run `x1`. again");
        let p = plan(&view(&pack).unwrap(), "Never run `x1`.\n");
        let out = apply(
            &pack,
            &p,
            &[],
            &[decided(&l, &["x2"], Choice::Enforce)],
            &[],
        )
        .unwrap();
        assert!(out.contains("id = \"l1-2\""), "{out}");
        assert!(out.contains("\"x2\""), "{out}");
    }
}
