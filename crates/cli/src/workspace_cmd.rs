//! `saiife workspace pair | devices | revoke | serve` (plan 29, Task 5):
//! the machine side of the Workspace link. `pair`, `devices` and `revoke`
//! call the daemon's control-socket ops (`workspace.*`); `serve` runs
//! `saiife-link`, the user-process half between a browser or phone and the
//! daemon's `link.sock`. Unix only: on Windows the command says so and
//! exits 5. Exit codes as `lockdown`: 0 ok, 2 refused or cancelled, 5 the
//! daemon cannot be reached (or this system has no Workspace link).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

/// The default port of the localhost UI.
const DEFAULT_PORT: u16 = 47810;

#[derive(Subcommand)]
pub enum WorkspaceAction {
    /// Pair a browser with this machine (shows a QR code and a link).
    Pair {
        /// A name for the browser (shown in the device list).
        #[arg(long)]
        label: Option<String>,
        /// The localhost UI instead of app.saiife.com.
        #[arg(long)]
        local: bool,
        /// The port of the localhost UI (with --local).
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// List paired browsers.
    Devices,
    /// Remove a paired browser.
    Revoke {
        /// The device id (`d-…`, as `saiife workspace devices` shows it).
        device: String,
    },
    /// Run the Workspace link: the localhost UI, and the hub if --hub is given.
    Serve {
        /// The port of the localhost UI (127.0.0.1 only).
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// A hub to connect to: a wss:// URL.
        #[arg(long)]
        hub: Option<String>,
    },
}

#[cfg(unix)]
/// The link a browser opens to pair. The offer travels in the URL
/// fragment: a browser never sends a fragment to a server.
pub fn pair_url(local: bool, port: u16, fragment: &str) -> String {
    if local {
        format!("http://localhost:{port}/#pair={fragment}")
    } else {
        format!("https://app.saiife.com/workspace#pair={fragment}")
    }
}

#[cfg(unix)]
/// The QR code of `url` as terminal text (two modules per character row,
/// with the quiet zone). A URL too long for a QR code gives an empty string.
pub fn qr_text(url: &str) -> String {
    use qrcode::render::unicode::Dense1x2;
    match qrcode::QrCode::new(url.as_bytes()) {
        Ok(code) => code.render::<Dense1x2>().quiet_zone(true).build(),
        Err(_) => String::new(),
    }
}

#[cfg(not(unix))]
pub fn run(_config: Option<PathBuf>, _action: WorkspaceAction) -> ExitCode {
    eprintln!("saiife: the Workspace link is not available on Windows yet");
    ExitCode::from(5)
}

#[cfg(unix)]
pub fn run(config: Option<PathBuf>, action: WorkspaceAction) -> ExitCode {
    imp::run(config, action)
}

#[cfg(unix)]
mod imp {
    use super::{pair_url, qr_text, WorkspaceAction};
    use crate::broker::{self, Target};
    use crate::secret_cmd::linux::{call_to, Stop};
    use crate::text::sanitize;
    use saiife_ipc::msg::{
        OP_WORKSPACE_DEVICES, OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM,
        OP_WORKSPACE_PAIR_STATUS, OP_WORKSPACE_REVOKE,
    };
    use serde_json::{json, Map, Value};
    use std::io::{BufRead, IsTerminal, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// A control call: `(op, args)` to the daemon.
    type Call<'a> = dyn FnMut(&str, Map<String, Value>) -> Result<Map<String, Value>, Stop> + 'a;

    pub fn run(config: Option<PathBuf>, action: WorkspaceAction) -> ExitCode {
        let done = match action {
            WorkspaceAction::Serve { port, hub } => return serve(config, port, hub),
            WorkspaceAction::Pair { label, local, port } => {
                resolve(config).and_then(|t| pair(&t, label, local, port))
            }
            WorkspaceAction::Devices => resolve(config).and_then(|t| devices(&t)),
            WorkspaceAction::Revoke { device } => resolve(config).and_then(|t| revoke(&t, &device)),
        };
        match done {
            Ok(()) => ExitCode::SUCCESS,
            Err(stop) => {
                let (code, m) = exit_of(stop);
                eprintln!("saiife: {m}");
                ExitCode::from(code)
            }
        }
    }

    fn resolve(config: Option<PathBuf>) -> Result<Target, Stop> {
        broker::resolve_here(config.as_deref()).map_err(Stop::Unavailable)
    }

    /// The exit code and message for a stop, as `lockdown`: refusals 2;
    /// an unreachable daemon, or a change made but not on record, 5.
    fn exit_of(stop: Stop) -> (u8, String) {
        match stop {
            Stop::Refused(m) | Stop::Forbidden(m) => (2, m),
            Stop::Unavailable(m) | Stop::NotFound(m) | Stop::Unrecorded(m) => (5, m),
        }
    }

    /// A call to the daemon. Granting power (accepting a pairing, revoking)
    /// may ask a non-root user for a password: re-authentication is
    /// prepared first (as `lockdown off`) and kept until the daemon answers.
    fn caller(
        t: &Target,
    ) -> impl FnMut(&str, Map<String, Value>) -> Result<Map<String, Value>, Stop> + '_ {
        move |op, mut args| {
            let grants = op == OP_WORKSPACE_REVOKE
                || (op == OP_WORKSPACE_PAIR_CONFIRM
                    && args.get("accept").and_then(Value::as_bool) == Some(true));
            let _held = if grants && !crate::win_locked::own_is_root() {
                let what = if op == OP_WORKSPACE_REVOKE {
                    "revoking a device"
                } else {
                    "pairing a device"
                };
                eprintln!("saiife: {what} (you may be asked for your password)");
                crate::approvals_cmd::prepare_reauth(&mut args)
                    .map_err(|e| eprintln!("saiife: warning: {e}"))
                    .ok()
            } else {
                None
            };
            call_to(t, op, args)
        }
    }

    fn pair(t: &Target, label: Option<String>, local: bool, port: u16) -> Result<(), Stop> {
        let tty = std::io::stdout().is_terminal();
        let stdin = std::io::stdin();
        let cancel = Arc::new(Cancel::default());
        watch_interrupt(Arc::clone(&cancel));
        let mut call = caller(t);
        let mut io = PairIo {
            out: &mut std::io::stdout(),
            input: &mut stdin.lock(),
            tty,
            now: &now_secs,
            sleep: &|| std::thread::sleep(Duration::from_secs(1)),
            cancel: &cancel,
        };
        pair_flow(&mut call, &mut io, label, local, port).map(|id| outln!("Paired {id}"))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// What Ctrl-C needs to say.
    #[derive(Default)]
    pub struct Cancel {
        /// The accept has been sent: the device may be paired.
        committing: AtomicBool,
    }

    /// Ctrl-C ends `pair` with exit 2. A thread waits for SIGINT (tokio's
    /// signal handling; no unsafe, no new crate).
    fn watch_interrupt(cancel: Arc<Cancel>) {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("interrupt".into())
            .spawn(move || {
                rt.block_on(async {
                    let Ok(mut sig) =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    else {
                        let _ = ready_tx.send(());
                        return std::future::pending::<()>().await;
                    };
                    let _ = ready_tx.send(());
                    sig.recv().await;
                });
                if cancel.committing.load(Ordering::SeqCst) {
                    eprintln!(
                        "\nsaiife: interrupted while confirming; check `saiife workspace devices`"
                    );
                } else {
                    eprintln!("\nsaiife: cancelled; nothing is paired");
                }
                std::process::exit(2);
            });
        // The handler is in place before the offer is made.
        if spawned.is_ok() {
            let _ = ready_rx.recv();
        }
    }

    /// The seams of the pair flow, so a test can drive it.
    pub struct PairIo<'a> {
        pub out: &'a mut dyn Write,
        pub input: &'a mut dyn BufRead,
        /// stdout is a terminal (the QR code is only drawn then).
        pub tty: bool,
        pub now: &'a dyn Fn() -> u64,
        /// One poll interval.
        pub sleep: &'a dyn Fn(),
        pub cancel: &'a Cancel,
    }

    /// The prompt shown when a browser asks to pair. The label is the
    /// browser's own text: sanitized.
    pub fn confirm_prompt(label: &str, short_code: &str) -> String {
        format!(
            "Browser \"{}\" shows: {}. Same code? [y/N] ",
            sanitize(label),
            sanitize(short_code)
        )
    }

    /// begin, show the offer, poll, ask, confirm. Returns the device id.
    pub fn pair_flow(
        call: &mut Call<'_>,
        io: &mut PairIo<'_>,
        label: Option<String>,
        local: bool,
        port: u16,
    ) -> Result<String, Stop> {
        let mut args = Map::new();
        if let Some(l) = label {
            args.insert("label".into(), json!(l));
        }
        let offer = call(OP_WORKSPACE_PAIR_BEGIN, args)?;
        let text = |m: &Map<String, Value>, k: &str| {
            m.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| Stop::Unavailable(format!("the daemon's answer has no {k}")))
        };
        let pair_id = text(&offer, "pair_id")?;
        let fragment = text(&offer, "fragment")?;
        let expires_at = offer.get("expires_at").and_then(Value::as_u64).unwrap_or(0);
        let url = pair_url(local, port, &fragment);
        // The fragment is a secret: it is shown here, once, inside the URL.
        if io.tty {
            let _ = write!(io.out, "{}", qr_text(&url));
        }
        let _ = writeln!(io.out, "{url}");
        let _ = writeln!(io.out, "Waiting for the browser (5 min)…");
        let _ = io.out.flush();
        let (label, code, _device) = loop {
            let mut a = Map::new();
            a.insert("pair_id".into(), json!(pair_id));
            let st = call(OP_WORKSPACE_PAIR_STATUS, a)?;
            match st.get("state").and_then(Value::as_str) {
                Some("requested") => {
                    let s = |k: &str| st.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                    break (s("label"), s("short_code"), s("device_id"));
                }
                Some("expired") => {
                    return Err(Stop::Refused(
                        "the pairing expired; nothing is paired".into(),
                    ))
                }
                _ => {}
            }
            if (io.now)() >= expires_at {
                return Err(Stop::Refused(
                    "the pairing expired; nothing is paired".into(),
                ));
            }
            (io.sleep)();
        };
        let _ = write!(io.out, "{}", confirm_prompt(&label, &code));
        let _ = io.out.flush();
        let mut line = String::new();
        let accept = io.input.read_line(&mut line).is_ok()
            && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        let mut a = Map::new();
        a.insert("pair_id".into(), json!(pair_id));
        a.insert("accept".into(), json!(accept));
        if accept {
            io.cancel.committing.store(true, Ordering::SeqCst);
        }
        let done = call(OP_WORKSPACE_PAIR_CONFIRM, a);
        io.cancel.committing.store(false, Ordering::SeqCst);
        let done = done?;
        if !accept {
            return Err(Stop::Refused("pairing rejected; nothing is paired".into()));
        }
        text(&done, "device_id")
    }

    fn devices(t: &Target) -> Result<(), Stop> {
        let a = call_to(t, OP_WORKSPACE_DEVICES, Map::new())?;
        let list = a.get("devices").and_then(Value::as_array);
        let Some(list) = list.filter(|l| !l.is_empty()) else {
            outln!("no paired browsers");
            return Ok(());
        };
        for d in list {
            let s = |k: &str| sanitize(d.get(k).and_then(Value::as_str).unwrap_or(""));
            outln!(
                "{}  {}  {}  {}",
                s("id"),
                s("state"),
                s("owner_user"),
                s("label")
            );
        }
        Ok(())
    }

    fn revoke(t: &Target, device: &str) -> Result<(), Stop> {
        let mut call = caller(t);
        let mut a = Map::new();
        a.insert("device_id".into(), json!(device));
        call(OP_WORKSPACE_REVOKE, a)?;
        outln!("Revoked {}", sanitize(device));
        Ok(())
    }

    fn serve(config: Option<PathBuf>, port: u16, hub: Option<String>) -> ExitCode {
        let (socket_dir, daemon_uid) = match resolve(config) {
            Ok(Target::Locked {
                socket_dir,
                owner_uid,
                ..
            })
            | Ok(Target::Personal {
                socket_dir,
                owner_uid,
                ..
            }) => (socket_dir, owner_uid),
            Err(stop) => {
                let (code, m) = exit_of(stop);
                eprintln!("saiife: {m}");
                return ExitCode::from(code);
            }
        };
        if let Some(h) = &hub {
            if !h.starts_with("wss://") {
                eprintln!("saiife: --hub must be a wss:// URL");
                return ExitCode::from(2);
            }
        }
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("saiife: cannot start the runtime: {e}");
                return ExitCode::from(5);
            }
        };
        outln!("Workspace on http://localhost:{port}/");
        let cfg = saiife_link::LinkConfig {
            socket_dir,
            daemon_uid,
            port,
            hub,
            hub_roots: None,
        };
        match rt.block_on(saiife_link::run(cfg)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("saiife: {e}");
                ExitCode::from(2)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn confirm_prompt_sanitizes_label() {
            let p = confirm_prompt("\x1b[2J evil", "123 456");
            assert!(!p.contains('\x1b'), "{p:?}");
            assert!(p.starts_with("Browser \""), "{p:?}");
            assert!(p.ends_with("shows: 123 456. Same code? [y/N] "), "{p:?}");
        }

        #[test]
        fn exit_codes_follow_lockdown() {
            assert_eq!(exit_of(Stop::Refused("x".into())).0, 2);
            assert_eq!(exit_of(Stop::Forbidden("x".into())).0, 2);
            assert_eq!(exit_of(Stop::Unavailable("x".into())).0, 5);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn pair_url_shapes() {
        let local = pair_url(true, 47810, "abc_-");
        assert_eq!(local, "http://localhost:47810/#pair=abc_-");
        let hub = pair_url(false, 47810, "abc_-");
        assert_eq!(hub, "https://app.saiife.com/workspace#pair=abc_-");
        for u in [&local, &hub] {
            let (before, after) = u.split_once('#').unwrap();
            assert_eq!(after, "pair=abc_-");
            assert!(!before.contains("abc_-") && !before.contains('?'), "{u}");
        }
    }

    #[test]
    fn qr_text_is_nonempty_unicode() {
        let q = qr_text(&pair_url(true, 47810, "abc"));
        assert!(q.lines().count() > 8, "{q}");
        assert!(!q.is_ascii(), "{q}");
        assert!(q.contains('\u{2588}') || q.contains('\u{2580}') || q.contains('\u{2584}'));
    }
}
