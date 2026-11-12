//! `saiife box spawn|ls|say|pause|resume|stop|discard|done|revise|reorder|
//! templates|gc` (plan 34): boxes through the daemon's `box.*` ops. Exit
//! codes: 0 ok, 2 refused (not found, wrong state, invalid, busy, lockdown),
//! 5 the daemon cannot be reached or has no boxes in this version.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum BoxAction {
    /// Start a box from a template, or queue it if the machine is full.
    #[command(visible_alias = "run-agent")]
    Spawn {
        /// The template to start from (see `saiife box templates`).
        #[arg(long, default_value = "claude-code")]
        template: String,
        /// The repository the box works on.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// What the agent should do.
        #[arg(long)]
        task: Option<String>,
        /// Start now or fail; never queue.
        #[arg(long)]
        now: bool,
        /// Print each step's milliseconds to stderr (the smoke script's).
        #[arg(long, hide = true)]
        timings: bool,
    },
    /// List your boxes (all boxes for an admin with --all).
    Ls {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Every user's boxes (admins only).
        #[arg(long)]
        all: bool,
    },
    /// Send a message to the agent in a running or paused box.
    Say {
        id: String,
        /// The message.
        msg: String,
    },
    /// Pause a running box.
    Pause { id: String },
    /// Resume a paused box.
    Resume { id: String },
    /// Turn a box's VM off; its work stays for review. A queued box is
    /// cancelled with `discard`.
    Stop {
        id: String,
        /// Keep a snapshot of the VM.
        #[arg(long)]
        keep: bool,
    },
    /// Delete a queued or finished box and its disks.
    Discard {
        id: String,
        /// Do not ask first.
        #[arg(long)]
        yes: bool,
    },
    /// Mark a box's work as finished.
    Done { id: String },
    /// Send a finished box back to work with a comment.
    Revise {
        id: String,
        /// What to change.
        comment: String,
    },
    /// Reorder the queue: list every queued box once, head first.
    Reorder { ids: Vec<String> },
    /// List the box templates.
    Templates {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Delete discarded boxes and the leftovers of failed starts.
    Gc,
    /// The pinned Cloud Hypervisor and firmware the boxes run on.
    Vmm {
        #[command(subcommand)]
        action: crate::box_vmm_cmd::VmmAction,
    },
    /// Base images for boxes.
    Image {
        #[command(subcommand)]
        action: crate::box_image_cmd::ImageAction,
    },
}

#[cfg(not(unix))]
pub fn run(config: Option<PathBuf>, action: BoxAction) -> ExitCode {
    let _ = (config, action);
    eprintln!("saiife: {}", saiife_system::NOT_SUPPORTED_OS);
    ExitCode::from(5)
}

#[cfg(unix)]
pub fn run(config: Option<PathBuf>, action: BoxAction) -> ExitCode {
    match imp::go(config.as_deref(), action) {
        Ok(()) => ExitCode::SUCCESS,
        Err(imp::Stop::Refused(m)) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            ExitCode::from(2)
        }
        Err(imp::Stop::Unavailable(m)) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            ExitCode::from(5)
        }
        Err(imp::Stop::Failed(m)) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            ExitCode::from(1)
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::BoxAction;
    use crate::broker::{self, Target};
    use crate::text::sanitize;
    use saiife_ipc::client::ClientError;
    use serde_json::{json, Map, Value};
    use std::io::{BufRead, IsTerminal, Write};
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// A spawn waits for the VM to boot.
    const CALL_TIMEOUT: Duration = Duration::from_secs(120);
    /// The longest task in `ls`, in characters.
    const TASK_COLS: usize = 40;
    const NEED_YES: &str = "discarding a box needs a yes. Run it in a terminal, or add --yes.";

    pub(super) enum Stop {
        Refused(String),
        Unavailable(String),
        /// A local job failed (`box image build`): exit 1.
        Failed(String),
    }

    type Args = Map<String, Value>;

    fn args<const N: usize>(kv: [(&str, Value); N]) -> Args {
        kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// One call on a fresh connection. `unavailable` (no boxes in this
    /// version) is exit 5 like an unreachable daemon; every other refusal is 2.
    fn call(t: &Target, op: &str, a: Args) -> Result<Args, Stop> {
        call_passing(t, op, a, &[])
    }

    /// [`call`], with `fds` passed to the daemon for this op (none: a
    /// plain call).
    fn call_passing(
        t: &Target,
        op: &str,
        a: Args,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<Args, Stop> {
        let down = |e: &ClientError| Stop::Unavailable(broker::unreachable(t, e));
        let mut c = broker::connect(t, Instant::now() + CONNECT_TIMEOUT).map_err(|e| down(&e))?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        let r = if fds.is_empty() {
            c.call(op, a, deadline)
        } else {
            c.call_with_fds(op, a, fds, deadline)
        };
        r.map_err(|e| match e {
            ClientError::Refused { code, message } if code == "unavailable" => {
                Stop::Unavailable(message)
            }
            ClientError::Refused { message, .. } => Stop::Refused(message),
            other => down(&other),
        })
    }

    /// `saiife box spawn` (plan 37): the repo disk is built here, as the
    /// user, and handed to the daemon as descriptors.
    mod spawn {
        use super::{args, call_passing, sanitize, Args, Stop};
        use crate::box_repo::{self, Snapshot};
        use crate::broker::Target;
        use saiife_boxhost::layout::Layout;
        use saiife_boxhost::tools::Tools;
        use saiife_wire::source::BoxId;
        use serde_json::{json, Value};
        use std::os::fd::AsFd;
        use std::path::{Path, PathBuf};
        use std::time::Instant;

        /// `--timings`: each step's milliseconds on stderr.
        struct Clock {
            on: bool,
            last: Instant,
        }

        impl Clock {
            fn step(&mut self, what: &str) {
                let now = Instant::now();
                if self.on {
                    let ms = now.duration_since(self.last).as_millis();
                    eprintln!("saiife: timing {what} {ms} ms");
                }
                self.last = now;
            }
        }

        /// The staging dir, removed however the spawn ends.
        struct Staged(Option<Snapshot>);

        impl Drop for Staged {
            fn drop(&mut self) {
                if let Some(s) = self.0.take() {
                    s.remove();
                }
            }
        }

        /// `$XDG_CACHE_HOME/saiife` (an absolute one), else
        /// `$HOME/.cache/saiife`.
        fn cache_dir() -> Result<PathBuf, Stop> {
            let abs = |k: &str| {
                std::env::var_os(k)
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
            };
            abs("XDG_CACHE_HOME")
                .or_else(|| abs("HOME").map(|h| h.join(".cache")))
                .map(|c| c.join("saiife"))
                .ok_or_else(|| Stop::Failed("cannot find your cache dir (HOME is not set)".into()))
        }

        /// The base manifest as a file of the staging dir (0600), open for
        /// reading.
        fn manifest_file(s: &Snapshot) -> Result<std::fs::File, Stop> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let p = s.dir().join(saiife_boxhost::paths::BASE_MANIFEST);
            let text = serde_json::to_vec(&s.manifest)
                .map_err(|e| Stop::Failed(format!("the base manifest: {e}")))?;
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&p)
                .map_err(|e| Stop::Failed(format!("{}: {e}", p.display())))?;
            f.write_all(&text)
                .map_err(|e| Stop::Failed(format!("{}: {e}", p.display())))?;
            Ok(f)
        }

        pub(in super::super) fn run(
            t: &Target,
            template: &str,
            repo: &Path,
            task: Option<String>,
            now: bool,
            timings: bool,
        ) -> Result<Args, Stop> {
            let mut clock = Clock {
                on: timings,
                last: Instant::now(),
            };
            let abs = std::fs::canonicalize(repo).map_err(|e| {
                Stop::Refused(format!("cannot read the repo {}: {e}", repo.display()))
            })?;
            let cache = cache_dir()?;
            let tools = Tools::system(&Layout::locked().vmm).with_env(&|k| std::env::var_os(k));
            let snap = box_repo::snapshot(&tools, &abs, &cache).map_err(Stop::Refused)?;
            for w in &snap.warnings {
                eprintln!("saiife: warning: {}", sanitize(w));
            }
            clock.step("snapshot");
            let mut staged = Staged(Some(snap));
            let Some(snap) = staged.0.as_mut() else {
                return Err(Stop::Failed("the snapshot went away".into()));
            };
            let img = box_repo::make_repo_image(&tools, snap).map_err(Stop::Failed)?;
            clock.step("image");
            let commit = box_repo::snapshot_commit(&tools, &abs, snap).map_err(Stop::Failed)?;
            clock.step("snapshot commit");
            let image = std::fs::File::open(&img)
                .map_err(|e| Stop::Failed(format!("{}: {e}", img.display())))?;
            let manifest = manifest_file(snap)?;
            let mut a = args([
                ("template", json!(template)),
                ("repo", json!(snap.manifest.repo)),
                ("repo_dir", json!(abs.to_string_lossy())),
                ("start", json!(if now { "now" } else { "queue" })),
            ]);
            if let Some(task) = task {
                a.insert("task".into(), json!(task));
            }
            let answer = call_passing(t, "box.spawn", a, &[image.as_fd(), manifest.as_fd()])?;
            drop((image, manifest));
            clock.step("spawn");
            let id = answer
                .get("box")
                .and_then(|b| b.get("id"))
                .and_then(Value::as_str)
                .and_then(|s| BoxId::parse(s).ok());
            match id {
                Some(id) => {
                    if let Err(e) = box_repo::set_base_ref(&tools, &abs, &id, &commit) {
                        eprintln!(
                            "saiife: warning: the box's base ref is not set ({}); land will recreate it",
                            sanitize(&e)
                        );
                    }
                }
                None => eprintln!(
                    "saiife: warning: the daemon named no box; land will recreate the base ref"
                ),
            }
            clock.step("base ref");
            drop(staged);
            clock.step("cleanup");
            Ok(answer)
        }
    }

    fn text<'a>(v: &'a Value, key: &str) -> &'a str {
        v.get(key).and_then(Value::as_str).unwrap_or("")
    }

    /// `box <id> <state>` from an answer's `box`.
    fn print_box(answer: &Args, fallback_state: &str) {
        let b = answer.get("box").cloned().unwrap_or(Value::Null);
        let state = b
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or(fallback_state);
        outln!("box {} {}", sanitize(text(&b, "id")), sanitize(state));
        if let Some(n) = b.get("queue_pos").and_then(Value::as_u64) {
            outln!("queue position {n}");
        }
    }

    pub(super) fn go(config: Option<&Path>, action: BoxAction) -> Result<(), Stop> {
        if let BoxAction::Vmm { action } = action {
            return match crate::box_vmm_cmd::run(config, action) {
                Ok(()) => Ok(()),
                Err(crate::box_vmm_cmd::Fail::Refused(m)) => Err(Stop::Refused(m)),
                Err(crate::box_vmm_cmd::Fail::Unavailable(m)) => Err(Stop::Unavailable(m)),
            };
        }
        if let BoxAction::Image { action } = action {
            return match crate::box_image_cmd::run(config, action) {
                Ok(()) => Ok(()),
                Err(crate::box_image_cmd::Fail::Failed(m)) => Err(Stop::Failed(m)),
                Err(crate::box_image_cmd::Fail::Unavailable(m)) => Err(Stop::Unavailable(m)),
            };
        }
        let t = broker::resolve_here(config).map_err(Stop::Unavailable)?;
        match action {
            BoxAction::Spawn {
                template,
                repo,
                task,
                now,
                timings,
            } => {
                let a = spawn::run(&t, &template, &repo, task, now, timings)?;
                print_box(&a, "");
            }
            BoxAction::Ls { json, all } => {
                let a = call(&t, "box.list", args([("all", json!(all))]))?;
                if json {
                    outln!(
                        "{}",
                        ascii_json(&json!({
                            "boxes": a.get("boxes").cloned().unwrap_or(json!([])),
                            "slots_total": a.get("slots_total").cloned().unwrap_or(json!(0)),
                            "slots_free": a.get("slots_free").cloned().unwrap_or(json!(0)),
                        }))
                    );
                } else {
                    print_table(&a);
                }
            }
            BoxAction::Say { id, msg } => {
                call(
                    &t,
                    "box.steer",
                    args([("box", json!(id)), ("msg", json!(msg))]),
                )?;
                outln!("sent to {}", sanitize(&id));
            }
            BoxAction::Pause { id } => per_box(&t, "box.pause", &id, Args::new())?,
            BoxAction::Resume { id } => per_box(&t, "box.resume", &id, Args::new())?,
            BoxAction::Stop { id, keep } => {
                per_box(&t, "box.stop", &id, args([("keep", json!(keep))]))?;
            }
            BoxAction::Done { id } => per_box(&t, "box.done", &id, Args::new())?,
            BoxAction::Revise { id, comment } => {
                per_box(&t, "box.revise", &id, args([("comment", json!(comment))]))?;
            }
            BoxAction::Discard { id, yes } => {
                let q = format!("Discard box {} and delete its disks?", sanitize(&id));
                let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
                let go = confirm(&q, yes, tty, &mut std::io::stdin().lock())?;
                if !go {
                    outln!("not discarded");
                    return Ok(());
                }
                let a = call(&t, "box.discard", args([("box", json!(id))]))?;
                let b = a.get("box").cloned().unwrap_or(Value::Null);
                outln!("box {} discarded", sanitize(text(&b, "id")));
            }
            BoxAction::Reorder { ids } => {
                call(&t, "box.reorder", args([("ids", json!(ids))]))?;
                outln!("queue reordered");
            }
            BoxAction::Templates { json } => {
                let a = call(&t, "box.templates", Args::new())?;
                if json {
                    outln!(
                        "{}",
                        ascii_json(&json!({
                            "templates": a.get("templates").cloned().unwrap_or(json!([])),
                            "warnings": a.get("warnings").cloned().unwrap_or(json!([])),
                        }))
                    );
                } else {
                    print_templates(&a);
                }
            }
            BoxAction::Vmm { .. } | BoxAction::Image { .. } => unreachable!("handled above"),
            BoxAction::Gc => {
                let a = call(&t, "box.gc", Args::new())?;
                let removed: Vec<String> = a
                    .get("removed")
                    .and_then(Value::as_array)
                    .map(|v| v.iter().filter_map(Value::as_str).map(sanitize).collect())
                    .unwrap_or_default();
                if removed.is_empty() {
                    outln!("nothing to remove");
                } else {
                    outln!("removed {}", removed.join(", "));
                }
                // gc goes on past a box it cannot remove; the first failure
                // comes after what it did remove.
                if let Some(e) = a.get("error").and_then(Value::as_str) {
                    return Err(Stop::Unavailable(format!("gc: {e}")));
                }
            }
        }
        Ok(())
    }

    fn per_box(t: &Target, op: &str, id: &str, mut extra: Args) -> Result<(), Stop> {
        // `box`, not `id`: the frame's own `id` is the request's.
        extra.insert("box".into(), json!(id));
        print_box(&call(t, op, extra)?, "");
        Ok(())
    }

    /// Asks `question` on stderr. `yes` skips it; with no terminal there is no
    /// one to ask, so it is a refusal.
    fn confirm(
        question: &str,
        yes: bool,
        tty: bool,
        input: &mut dyn BufRead,
    ) -> Result<bool, Stop> {
        if yes {
            return Ok(true);
        }
        if !tty {
            return Err(Stop::Refused(NEED_YES.into()));
        }
        eprint!("{question} [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        input
            .read_line(&mut line)
            .map_err(|e| Stop::Refused(format!("cannot read the answer: {e}")))?;
        let a = line.trim().to_ascii_lowercase();
        Ok(a == "y" || a == "yes")
    }

    /// `3m`, `2h`, `1d`.
    pub(super) fn age(secs: u64) -> String {
        match secs {
            s if s < 3600 => format!("{}m", s / 60),
            s if s < 86_400 => format!("{}h", s / 3600),
            s => format!("{}d", s / 86_400),
        }
    }

    /// Allocated MiB as `412M`, or `3.1G` from 1 GiB.
    pub(super) fn disk(mib: u64) -> String {
        if mib < 1024 {
            format!("{mib}M")
        } else {
            format!("{:.1}G", mib as f64 / 1024.0)
        }
    }

    /// The sanitized task, at most [`TASK_COLS`] characters.
    pub(super) fn short_task(task: &str) -> String {
        let t = sanitize(task);
        if t.chars().count() <= TASK_COLS {
            return t;
        }
        let mut cut: String = t.chars().take(TASK_COLS - 1).collect();
        cut.push('…');
        cut
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// A table as lines: columns padded to the widest cell, the last one
    /// not padded. A row's trailer, if any, is a line under it.
    pub(super) fn render(head: &[&str], rows: &[(Vec<String>, Option<String>)]) -> Vec<String> {
        let mut w: Vec<usize> = head.iter().map(|h| h.chars().count()).collect();
        for (r, _) in rows {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.chars().count());
            }
        }
        let line = |cells: &[&str]| {
            let mut s = String::new();
            for (i, c) in cells.iter().enumerate() {
                if i + 1 == cells.len() {
                    s.push_str(c);
                } else {
                    s.push_str(&format!("{:<w$}  ", c, w = w[i]));
                }
            }
            s.trim_end().to_string()
        };
        let mut out = vec![line(head)];
        for (r, trailer) in rows {
            let cells: Vec<&str> = r.iter().map(String::as_str).collect();
            out.push(line(&cells));
            out.extend(trailer.clone());
        }
        out
    }

    /// The `ls` table for a `box.list` answer's `boxes`, at time `now`.
    pub(super) fn box_lines(boxes: &[Value], now: u64) -> Vec<String> {
        let head = [
            "ID", "STATE", "TEMPLATE", "REPO", "AGE", "DISK", "QUEUE", "TASK",
        ];
        let rows: Vec<(Vec<String>, Option<String>)> = boxes
            .iter()
            .map(|b| {
                let created = b.get("created_at").and_then(Value::as_u64).unwrap_or(now);
                let cells = vec![
                    sanitize(text(b, "id")),
                    sanitize(text(b, "state")),
                    sanitize(text(b, "template")),
                    sanitize(text(b, "repo")),
                    age(now.saturating_sub(created)),
                    b.get("disk_mib")
                        .and_then(Value::as_u64)
                        .map_or_else(|| "-".to_string(), disk),
                    b.get("queue_pos")
                        .and_then(Value::as_u64)
                        .map_or_else(|| "-".to_string(), |n| n.to_string()),
                    short_task(text(b, "task")),
                ];
                let error = b
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|e| !e.is_empty())
                    .map(|e| format!("  error: {}", sanitize(e)));
                (cells, error)
            })
            .collect();
        render(&head, &rows)
    }

    fn print_table(a: &Args) {
        let boxes: &[Value] = a
            .get("boxes")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        for l in box_lines(boxes, now_secs()) {
            outln!("{l}");
        }
        let n = |k: &str| a.get(k).and_then(Value::as_u64).unwrap_or(0);
        outln!("slots: {} of {} free", n("slots_free"), n("slots_total"));
    }

    /// `v` as JSON with every non-ASCII character of a string written as
    /// `\uXXXX` (a surrogate pair above the BMP): same data, and a bidi or
    /// format character from the daemon never reaches the terminal raw.
    pub(super) fn ascii_json(v: &Value) -> String {
        use serde::Serialize;
        struct Ascii;
        impl serde_json::ser::Formatter for Ascii {
            fn write_string_fragment<W: ?Sized + std::io::Write>(
                &mut self,
                w: &mut W,
                fragment: &str,
            ) -> std::io::Result<()> {
                let mut buf = [0u16; 2];
                for c in fragment.chars() {
                    if c.is_ascii() {
                        w.write_all(&[c as u8])?;
                    } else {
                        for u in c.encode_utf16(&mut buf) {
                            write!(w, "\\u{u:04x}")?;
                        }
                    }
                }
                Ok(())
            }
        }
        let mut out = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut out, Ascii);
        if v.serialize(&mut ser).is_err() {
            return "null".into();
        }
        String::from_utf8(out).unwrap_or_default()
    }

    fn print_templates(a: &Args) {
        let list: &[Value] = a
            .get("templates")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        let flag = |t: &Value, k: &str| t.get(k).and_then(Value::as_bool).unwrap_or(false);
        let rows: Vec<(Vec<String>, Option<String>)> = list
            .iter()
            .map(|t| {
                let mut notes = Vec::new();
                if flag(t, "has_secrets") {
                    notes.push("secrets");
                }
                if flag(t, "has_egress") {
                    notes.push("egress");
                }
                (
                    vec![
                        sanitize(text(t, "name")),
                        notes.join(","),
                        sanitize(text(t, "description")),
                    ],
                    None,
                )
            })
            .collect();
        for l in render(&["NAME", "NEEDS", "DESCRIPTION"], &rows) {
            outln!("{l}");
        }
        for w in a
            .get("warnings")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
        {
            eprintln!(
                "saiife: template {}: {}",
                sanitize(text(w, "file")),
                sanitize(text(w, "reason"))
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn disk_units() {
            assert_eq!(disk(0), "0M");
            assert_eq!(disk(412), "412M");
            assert_eq!(disk(3174), "3.1G");
        }

        #[test]
        fn age_units() {
            assert_eq!(age(5), "0m");
            assert_eq!(age(180), "3m");
            assert_eq!(age(7200), "2h");
            assert_eq!(age(90_000), "1d");
        }

        #[test]
        fn task_is_cut_and_sanitized() {
            assert_eq!(short_task("a\nb"), "a⏎b");
            assert_eq!(short_task(&"x".repeat(40)), "x".repeat(40));
            let c = short_task(&"x".repeat(41));
            assert_eq!(c.chars().count(), 40);
            assert!(c.ends_with('…'));
            assert!(!short_task("a\u{202e}").contains('\u{202e}'));
        }

        #[test]
        fn table_shows_a_boxs_error_under_it() {
            let boxes = vec![
                json!({"id": "b1", "state": "discarded", "template": "claude-code",
                       "repo": "r", "task": "t", "created_at": 0, "queue_pos": null,
                       "error": "boot failed: no kvm\u{202e}"}),
                json!({"id": "b2", "state": "running", "template": "claude-code",
                       "repo": "r", "task": "u", "created_at": 0}),
            ];
            let lines = box_lines(&boxes, 7200);
            assert_eq!(lines.len(), 4, "{lines:?}");
            assert!(lines[0].starts_with("ID  STATE"), "{lines:?}");
            assert!(lines[1].starts_with("b1  discarded"), "{lines:?}");
            assert_eq!(lines[2], "  error: boot failed: no kvm\\u{202E}");
            assert!(lines[3].starts_with("b2  running"), "{lines:?}");
            assert!(lines[3].contains("2h"), "{lines:?}");
        }

        #[test]
        fn ascii_json_escapes_and_round_trips() {
            let v = json!({"k\u{e9}": "a\u{202e}b \u{1F600} \"q\" \n"});
            let s = ascii_json(&v);
            assert!(s.is_ascii(), "{s}");
            assert!(s.contains("\\u202e"), "{s}");
            assert!(s.contains("\\ud83d\\ude00"), "{s}");
            assert_eq!(serde_json::from_str::<Value>(&s).unwrap(), v);
        }

        #[test]
        fn confirm_rules() {
            let mut none = std::io::Cursor::new(Vec::new());
            assert!(matches!(confirm("q", true, false, &mut none), Ok(true)));
            assert!(matches!(
                confirm("q", false, false, &mut none),
                Err(Stop::Refused(_))
            ));
            let mut y = std::io::Cursor::new(b"YES\n".to_vec());
            assert!(matches!(confirm("q", false, true, &mut y), Ok(true)));
            let mut n = std::io::Cursor::new(b"\n".to_vec());
            assert!(matches!(confirm("q", false, true, &mut n), Ok(false)));
        }
    }
}
