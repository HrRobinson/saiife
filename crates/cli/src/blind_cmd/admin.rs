//! `saiife blind keys | methods | data` (plan 48 T5): the stand-in keys,
//! the approved methods and a dataset's data, through the daemon's
//! `blind.*` ops. Rotating or deleting keys, approving or removing a
//! method and loosening a column take a touch on the user's key (plan 48
//! T3: `blind.touch.begin`, the key, `blind.touch.commit`). Deleting keys
//! and removing a dataset first ask the user to type the dataset's name.
//!
//! `data class` writes `policy.d/blind-<dataset>.toml` (R48-8): a stricter
//! class at once, a looser one after a `blind:loosen` touch (the daemon
//! writes the grant); then the policy is reloaded, and when that fails the
//! previous file is put back.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum KeysAction {
    /// New stand-ins from now on: rotate the dataset's stand-in key (a
    /// touch, blind:keys).
    Rotate {
        /// The dataset (default: the only one you manage).
        #[arg(long)]
        dataset: Option<String>,
    },
    /// Delete the dataset's keys: its stand-ins can never be linked back
    /// to anyone, and it needs a refresh. Asks you to type the dataset's
    /// name, then a touch (blind:keys).
    Delete {
        #[arg(long)]
        dataset: String,
    },
}

#[derive(Subcommand)]
pub enum MethodsAction {
    /// The approved methods of a dataset (never their text).
    Ls {
        /// The dataset (default: the only one you may ask).
        #[arg(long)]
        dataset: Option<String>,
    },
    /// Approve the method of an answered ask for reuse (approvers; a
    /// touch, blind:approve).
    Approve {
        /// The ask id the approve hint printed.
        ask: String,
    },
    /// Remove an approved method (approvers; a touch, blind:approve).
    Rm {
        /// The method id (`saiife blind methods ls`).
        id: String,
        /// The dataset (default: the only one you manage).
        #[arg(long)]
        dataset: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DataAction {
    /// Build the dataset again from its source, showing the progress until
    /// it is live. A file source is opened here and passed to the daemon.
    Refresh {
        /// The dataset (default: the only one you manage).
        #[arg(long)]
        dataset: Option<String>,
        /// The source file (csv, xlsx or sqlite); asked for when missing.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Remove the dataset's data: its snapshot, its stand-in keys and its
    /// approved methods. Asks you to type the dataset's name.
    Rm {
        #[arg(long)]
        dataset: String,
    },
    /// Change a column's class in policy: identifier, quasi, sensitive,
    /// free_text or public. A looser class takes a touch (blind:loosen);
    /// names, IDs and amounts are never public.
    Class {
        /// The dataset.
        dataset: String,
        /// The column, as table.column.
        column: String,
        /// The new class.
        class: String,
    },
}

#[cfg(target_os = "linux")]
pub(super) use imp::{data, keys, methods};

#[cfg(target_os = "linux")]
mod imp {
    use super::super::ask::touch;
    use super::super::imp::{args, call, call_fds, s, Stop, READ_TIMEOUT};
    use super::super::{policy_file, Prompter};
    use super::{DataAction, KeysAction, MethodsAction};
    use crate::broker::Target;
    use crate::text::sanitize;
    use saiife_policy::blind::{BlindSource, ColumnCfg, COLUMN_CLASSES};
    use saiife_shield::schema::ColumnClass;
    use serde_json::{json, Map, Value};
    use std::os::fd::AsFd;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::Duration;

    /// A refresh is polled once a second, for at most this many polls.
    const MAX_POLLS: u32 = 6 * 3600;
    const POLL: Duration = Duration::from_secs(1);

    /// Which role picks the default dataset.
    #[derive(Clone, Copy)]
    enum Role {
        /// Users and approvers (`methods ls`).
        Ask,
        /// Admins and approvers (keys, refresh, method rm).
        Manage,
    }

    /// The dataset to act on: `given`, else the only one the user has
    /// `role` on (from `blind.status`). The daemon checks the role anyway.
    fn which(t: &Target, given: Option<String>, role: Role) -> Result<String, Stop> {
        if let Some(d) = given {
            return Ok(d);
        }
        let v = Value::Object(call(t, "blind.status", Map::new(), READ_TIMEOUT)?);
        let has = |d: &Value, k: &str| d["role"].get(k).and_then(Value::as_bool) == Some(true);
        let names: Vec<String> = v
            .get("datasets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|d| match role {
                Role::Ask => has(d, "user") || has(d, "approver"),
                Role::Manage => has(d, "admin") || has(d, "approver"),
            })
            .map(|d| s(d, "name").to_string())
            .collect();
        match names.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(Stop::Refused(
                "you have no dataset to do this on: see saiife blind status".into(),
            )),
            many => Err(Stop::Refused(format!(
                "name the dataset with --dataset (one of: {})",
                many.iter()
                    .map(|n| sanitize(n))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// The user types `name` to go on (deleting keys, removing a dataset).
    fn confirm_name(p: &mut dyn Prompter, prompt: &str, name: &str) -> Result<(), Stop> {
        if !p.is_interactive() {
            return Err(Stop::Refused(format!(
                "this needs the dataset name typed to go on: run it in a terminal ({})",
                sanitize(name)
            )));
        }
        match p.line(prompt) {
            Ok(typed) if typed == name => Ok(()),
            _ => Err(Stop::Refused(format!(
                "that is not {}; nothing was done",
                sanitize(name)
            ))),
        }
    }

    fn u(v: &Map<String, Value>, k: &str) -> u64 {
        v.get(k).and_then(Value::as_u64).unwrap_or(0)
    }

    fn st<'a>(v: &'a Map<String, Value>, k: &str) -> &'a str {
        v.get(k).and_then(Value::as_str).unwrap_or("")
    }

    // ------------------------------------------------------------ keys ----

    pub(crate) fn delete_keys_prompt(ds: &str) -> String {
        format!(
            "This deletes the stand-in keys of {ds}: its stand-ins can never be linked back to anyone, and it needs a refresh. Type the dataset name to go on: "
        )
    }

    /// `saiife blind keys rotate | delete`.
    pub(crate) fn keys(t: &Target, a: KeysAction, p: &mut dyn Prompter) -> Result<ExitCode, Stop> {
        match a {
            KeysAction::Rotate { dataset } => {
                let ds = which(t, dataset, Role::Manage)?;
                let r = touch(
                    t,
                    args([
                        ("purpose", json!("keys")),
                        ("dataset", json!(ds)),
                        ("action", json!("rotate")),
                    ]),
                )?;
                outln!(
                    "rotated the stand-in key of {}: version {}",
                    sanitize(&ds),
                    u(&r, "version")
                );
            }
            KeysAction::Delete { dataset } => {
                let shown = sanitize(&dataset);
                confirm_name(p, &delete_keys_prompt(&shown), &dataset)?;
                touch(
                    t,
                    args([
                        ("purpose", json!("keys")),
                        ("dataset", json!(dataset)),
                        ("action", json!("delete")),
                    ]),
                )?;
                outln!("deleted the stand-in keys of {shown}");
                outln!("it needs a refresh: saiife blind data refresh --dataset {shown}");
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    // --------------------------------------------------------- methods ----

    /// One approved method as lines (metadata only, never its text).
    pub(crate) fn method_lines(m: &Value) -> Vec<String> {
        let status = &m["status"];
        let state = match (s(status, "state"), s(status, "reason")) {
            ("", _) => "unknown".to_string(),
            (x, "") => sanitize(x),
            (x, why) => format!("{} ({})", sanitize(x), sanitize(why)),
        };
        let tags: Vec<String> = m
            .get("param_tags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(sanitize)
            .collect();
        let mut out = vec![format!(
            "{}  v{}  {}  {state}  approved by {} at {}",
            sanitize(s(m, "id")),
            m.get("version").and_then(Value::as_u64).unwrap_or(0),
            sanitize(s(m, "lang")),
            sanitize(s(m, "approved_by")),
            sanitize(s(m, "approved_at")),
        )];
        let mut t = format!("  template \"{}\"", sanitize(s(m, "template_key")));
        if !tags.is_empty() {
            t.push_str(&format!(" ({})", tags.join(", ")));
        }
        out.push(t);
        out
    }

    /// `saiife blind methods ls | approve | rm`.
    pub(crate) fn methods(t: &Target, a: MethodsAction) -> Result<ExitCode, Stop> {
        match a {
            MethodsAction::Ls { dataset } => {
                let ds = which(t, dataset, Role::Ask)?;
                let v = Value::Object(call(
                    t,
                    "blind.methods.list",
                    args([("dataset", json!(ds))]),
                    READ_TIMEOUT,
                )?);
                let list = v
                    .get("methods")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if list.is_empty() {
                    outln!("no approved methods for {}", sanitize(&ds));
                }
                for m in &list {
                    for l in method_lines(m) {
                        outln!("{l}");
                    }
                }
            }
            MethodsAction::Approve { ask } => {
                let r = touch(
                    t,
                    args([("purpose", json!("approve")), ("ask", json!(ask))]),
                )?;
                outln!(
                    "approved method {} (version {}) for reuse",
                    sanitize(st(&r, "method")),
                    u(&r, "version")
                );
            }
            MethodsAction::Rm { id, dataset } => {
                let ds = which(t, dataset, Role::Manage)?;
                touch(
                    t,
                    args([
                        ("purpose", json!("method_rm")),
                        ("dataset", json!(ds)),
                        ("method", json!(id)),
                    ]),
                )?;
                outln!(
                    "removed approved method {} from {}",
                    sanitize(&id),
                    sanitize(&ds)
                );
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    // ------------------------------------------------------------ data ----

    pub(crate) fn rm_prompt(ds: &str) -> String {
        format!(
            "This removes {ds}: its snapshot, its stand-in keys and its approved methods. Type the dataset name to go on: "
        )
    }

    /// `saiife blind data refresh | rm | class`.
    pub(crate) fn data(t: &Target, a: DataAction, p: &mut dyn Prompter) -> Result<ExitCode, Stop> {
        match a {
            DataAction::Refresh { dataset, file } => refresh(t, dataset, file, p),
            DataAction::Rm { dataset } => {
                let shown = sanitize(&dataset);
                confirm_name(p, &rm_prompt(&shown), &dataset)?;
                let r = call(
                    t,
                    "blind.data.rm",
                    args([("dataset", json!(dataset))]),
                    READ_TIMEOUT,
                )?;
                if r.get("removed").and_then(Value::as_bool) == Some(true) {
                    outln!("removed {shown}");
                } else {
                    outln!("{shown} has no data here; nothing was removed");
                }
                if let Ok(Some(_)) = policy_file::read_dataset(t, &dataset) {
                    if let Ok(path) = policy_file::dataset_path(t, &dataset) {
                        outln!(
                            "its policy stays in {}: remove that file, then saiife policy reload",
                            sanitize(&path.display().to_string())
                        );
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
            DataAction::Class {
                dataset,
                column,
                class,
            } => class_cmd(t, &dataset, &column, &class),
        }
    }

    /// The source of `ds` in the policy this CLI can read (the daemon's
    /// config and its drop-ins); `None` when it cannot tell.
    fn source_of(t: &Target, ds: &str) -> Option<BlindSource> {
        let l = saiife_policy::load_system(t.config()).ok()?;
        l.config
            .blind
            .dataset
            .into_iter()
            .find(|d| d.name == ds)
            .map(|d| d.source)
    }

    /// `saiife blind data refresh`: the source file opened here and passed
    /// (R47-5), then `blind.status` once a second until live or failed.
    fn refresh(
        t: &Target,
        dataset: Option<String>,
        file: Option<PathBuf>,
        p: &mut dyn Prompter,
    ) -> Result<ExitCode, Stop> {
        let ds = which(t, dataset, Role::Manage)?;
        let shown = sanitize(&ds);
        let needs_file = match source_of(t, &ds) {
            Some(BlindSource::Postgres { .. }) => None,
            Some(
                BlindSource::Csv { file_name }
                | BlindSource::Xlsx { file_name }
                | BlindSource::Sqlite { file_name },
            ) => Some(Some(file_name)),
            // Unknown here: a given file is passed, the daemon says the rest.
            None => file.is_some().then_some(None),
        };
        let path = match (needs_file, file) {
            (None, _) => None,
            (Some(_), Some(f)) => Some(f),
            (Some(name), None) => {
                if !p.is_interactive() {
                    return Err(Stop::Refused(format!(
                        "the refresh of {shown} reads its source file: pass --file <path>"
                    )));
                }
                let hint = name
                    .map(|n| format!(" ({})", sanitize(&n)))
                    .unwrap_or_default();
                let typed = p
                    .line(&format!("The source file of {shown}{hint}: "))
                    .map_err(Stop::Refused)?;
                if typed.is_empty() {
                    return Err(Stop::Refused("no file was given; nothing was done".into()));
                }
                Some(PathBuf::from(typed))
            }
        };
        let opened = match &path {
            Some(f) => Some(open_source(f)?),
            None => None,
        };
        let fds: Vec<_> = opened.iter().map(|f| f.as_fd()).collect();
        call_fds(
            t,
            "blind.data.refresh",
            args([("dataset", json!(ds))]),
            &fds,
            READ_TIMEOUT,
        )?;
        drop(opened);
        eprintln!("refreshing {shown}");
        watch(t, &ds)
    }

    /// The source file, read only; never a directory or a FIFO.
    fn open_source(f: &Path) -> Result<std::fs::File, Stop> {
        use std::os::unix::fs::OpenOptionsExt;
        let shown = sanitize(&f.display().to_string());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(f)
            .map_err(|e| Stop::Refused(format!("cannot open {shown}: {e}")))?;
        let regular = file.metadata().map(|m| m.is_file()).unwrap_or(false);
        if !regular {
            return Err(Stop::Refused(format!("{shown} is not a regular file")));
        }
        Ok(file)
    }

    /// The refresh's progress line from a dataset's status.
    pub(crate) fn phase_line(d: &Value) -> String {
        let p = &d["progress"];
        let phase = sanitize(s(p, "phase"));
        let (done, total) = (
            p.get("done").and_then(Value::as_u64).unwrap_or(0),
            p.get("total").and_then(Value::as_u64).unwrap_or(0),
        );
        if total > 0 {
            format!("  {phase} {done}/{total}")
        } else {
            format!("  {phase}")
        }
    }

    /// The last refresh's failure among a dataset's warnings.
    fn failure(d: &Value) -> Option<String> {
        d.get("warnings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .find_map(|w| w.strip_prefix("the last refresh failed: "))
            .map(sanitize)
    }

    /// Polls `blind.status` once a second, printing each new phase, until
    /// the dataset is live (exit 0) or the refresh failed (exit 5). A
    /// dataset that is no longer shown ends the wait at once.
    fn watch(t: &Target, ds: &str) -> Result<ExitCode, Stop> {
        let shown = sanitize(ds);
        let mut last = String::new();
        for _ in 0..MAX_POLLS {
            let v = Value::Object(call(t, "blind.status", Map::new(), READ_TIMEOUT)?);
            let d = v
                .get("datasets")
                .and_then(Value::as_array)
                .and_then(|l| l.iter().find(|d| s(d, "name") == ds))
                .cloned();
            let Some(d) = d else {
                return Err(Stop::Refused(format!(
                    "{shown} is no longer shown to you: see saiife blind status"
                )));
            };
            match s(&d, "state") {
                "refreshing" => {
                    let l = phase_line(&d);
                    if l != last {
                        eprintln!("{l}");
                        last = l;
                    }
                }
                "live" => {
                    if let Some(why) = failure(&d) {
                        return Err(Stop::Unavailable(format!(
                            "the refresh of {shown} failed: {why}"
                        )));
                    }
                    outln!("{shown} is live");
                    for w in d
                        .get("warnings")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        outln!("  ! {}", sanitize(w));
                    }
                    return Ok(ExitCode::SUCCESS);
                }
                other => {
                    let why = failure(&d)
                        .or_else(|| Some(sanitize(s(&d, "reason"))).filter(|r| !r.is_empty()))
                        .unwrap_or_else(|| sanitize(other));
                    return Err(Stop::Unavailable(format!(
                        "the refresh of {shown} failed: {why}"
                    )));
                }
            }
            std::thread::sleep(POLL);
        }
        Err(Stop::Unavailable(format!(
            "{shown} is still refreshing: see saiife blind status"
        )))
    }

    /// The class of `name` (one of [`COLUMN_CLASSES`]).
    fn parse_class(name: &str) -> Option<ColumnClass> {
        if !COLUMN_CLASSES.contains(&name) {
            return None;
        }
        serde_json::from_value(Value::String(name.to_string())).ok()
    }

    /// The text when a dataset is not in a file `saiife blind` wrote.
    fn defined_elsewhere(ds: &str, path: &Path) -> String {
        format!(
            "{ds} is not defined in {} (the file saiife blind writes): change its class where it is defined, then saiife policy reload",
            path.display()
        )
    }

    /// `saiife blind data class <dataset> <table.column> <class>` (R48-8).
    fn class_cmd(t: &Target, ds: &str, column: &str, class: &str) -> Result<ExitCode, Stop> {
        let to = parse_class(class).ok_or_else(|| {
            Stop::Refused(format!(
                "the class must be one of: {}",
                COLUMN_CLASSES.join(", ")
            ))
        })?;
        let ok_column = column
            .split_once('.')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('.'));
        if !ok_column {
            return Err(Stop::Refused(format!(
                "{} is not a column: write it as table.column",
                sanitize(column)
            )));
        }
        let path = policy_file::dataset_path(t, ds).map_err(Stop::Refused)?;
        let shown_ds = sanitize(ds);
        let shown_path = sanitize(&path.display().to_string());
        let mut d = policy_file::read_dataset(t, ds)
            .map_err(|e| Stop::Refused(sanitize(&e)))?
            .ok_or_else(|| Stop::Refused(sanitize(&defined_elsewhere(ds, &path))))?;
        // A column the policy does not list is sensitive (plan 47).
        let from_name = d
            .columns
            .get(column)
            .map_or("sensitive".to_string(), |c| c.class.clone());
        let from = parse_class(&from_name).unwrap_or(ColumnClass::Sensitive);
        let shown_col = sanitize(column);
        if from == to {
            outln!("{shown_col} is {class} in policy already; nothing was changed");
            return Ok(ExitCode::SUCCESS);
        }
        let looser = to.is_looser_than(from);
        if looser {
            // The daemon checks the class in force, refuses names, IDs and
            // amounts as public, then writes the grant (loosen.json).
            touch(
                t,
                args([
                    ("purpose", json!("loosen")),
                    ("dataset", json!(ds)),
                    ("column", json!(column)),
                    ("to", json!(class)),
                ]),
            )?;
        }
        let before = policy_file::previous(&path).map_err(Stop::Unavailable)?;
        let entry = d.columns.entry(column.to_string()).or_insert(ColumnCfg {
            class: String::new(),
            alias: None,
        });
        entry.class = class.to_string();
        policy_file::write_dataset(t, &d).map_err(|e| Stop::Refused(sanitize(&e)))?;
        if let Err(why) = policy_file::reload(t) {
            let back = match before.restore(t) {
                Ok(()) => format!("{shown_path} was put back as it was"),
                Err(e) => format!("and {} could not be put back: {}", shown_path, sanitize(&e)),
            };
            return Err(Stop::Refused(format!(
                "the policy did not load, so the change was not made: {}; {back}",
                sanitize(&why)
            )));
        }
        let how = if looser {
            "looser, with a blind:loosen touch"
        } else {
            "stricter, so no touch was needed"
        };
        outln!("{shown_col} is now {class} in {shown_path} ({how}; it was {from_name})");
        outln!("it applies at the next refresh: saiife blind data refresh --dataset {shown_ds}");
        Ok(ExitCode::SUCCESS)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_texts() {
            assert_eq!(
                delete_keys_prompt("crm"),
                "This deletes the stand-in keys of crm: its stand-ins can never be linked back to anyone, and it needs a refresh. Type the dataset name to go on: "
            );
            assert_eq!(
                rm_prompt("crm"),
                "This removes crm: its snapshot, its stand-in keys and its approved methods. Type the dataset name to go on: "
            );
        }

        #[test]
        fn classes_and_lines() {
            assert_eq!(parse_class("free_text"), Some(ColumnClass::FreeText));
            assert_eq!(parse_class("Public"), None);
            assert_eq!(parse_class("secret"), None);
            let m = json!({"id": "m-balance-v1", "version": 1, "lang": "en",
                "template_key": "balance of {customer}", "param_tags": ["customer"],
                "approved_by": "me", "approved_at": "t",
                "status": {"state": "suspended", "reason": "replaced by v2"}});
            assert_eq!(
                method_lines(&m),
                [
                    "m-balance-v1  v1  en  suspended (replaced by v2)  approved by me at t",
                    "  template \"balance of {customer}\" (customer)"
                ]
            );
            assert_eq!(
                phase_line(&json!({"progress": {"phase": "index", "done": 2, "total": 5}})),
                "  index 2/5"
            );
            assert_eq!(
                failure(&json!({"warnings": ["x", "the last refresh failed: bad \u{1b}"]})),
                Some("bad \\x1b".to_string())
            );
        }

        #[test]
        fn a_wrong_name_does_nothing() {
            let mut p = super::super::super::prompt::Script {
                answers: ["crn".to_string()].into_iter().collect(),
                prompts: Vec::new(),
                interactive: true,
            };
            assert!(matches!(
                confirm_name(&mut p, &rm_prompt("crm"), "crm"),
                Err(Stop::Refused(m)) if m == "that is not crm; nothing was done"
            ));
            p.interactive = false;
            assert!(confirm_name(&mut p, "x", "crm").is_err());
        }
    }
}
