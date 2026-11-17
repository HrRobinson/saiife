//! The Workspace link (plan 29): the user-process half between a browser or
//! phone and saiifed's `link.sock`. The daemon decides; this relays.
#![forbid(unsafe_code)]

pub mod assets;
pub mod daemon;
#[cfg(unix)]
pub mod hub;
#[cfg(unix)]
pub mod local;
pub mod ws;

pub use daemon::{Daemon, LinkError, MAX_DAEMON_CALLS};

#[cfg(not(unix))]
pub(crate) const WINDOWS_MSG: &str = "the Workspace link is not available on Windows yet";

pub struct LinkConfig {
    pub socket_dir: std::path::PathBuf,
    pub daemon_uid: u32,
    pub port: u16,
    pub hub: Option<String>,
    /// Tests; `None` = the platform's native roots.
    pub hub_roots: Option<rustls::RootCertStore>,
}

/// Configuration of the hub client (`--hub`).
pub struct HubConfig {
    /// `wss://host[:port]/v1/link` (see [`hub`]).
    pub url: String,
    /// The roots the hub's certificate must chain to.
    pub roots: rustls::RootCertStore,
    /// Tests only: connect here instead of resolving the URL's host (SNI
    /// and `Host` still come from the URL).
    pub connect: Option<std::net::SocketAddr>,
    /// Timings and rates; `HubOpts::default()` outside tests.
    pub opts: HubOpts,
}

/// The hub client's timings and rates (the defaults are `hub`'s constants
/// and `ws::PING_INTERVAL` / `ws::PONG_TIMEOUT`); the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct HubOpts {
    pub ping_interval: std::time::Duration,
    /// The connection is dropped this long after the last pong.
    pub pong_timeout: std::time::Duration,
    /// From a session's `open` to its sealed channel.
    pub handshake_timeout: std::time::Duration,
    /// Hub `open`s accepted.
    pub opens: Rate,
    /// Session `seal_hello`s accepted (each asks the daemon to sign).
    pub seal_hellos: Rate,
    /// How often the daemon is asked for new Workspace events
    /// (`workspace.wake`) while the hub link is up.
    pub wake_poll: std::time::Duration,
    /// At most one `{"t":"wake"}` this often; the events in between are
    /// coalesced into one wake when it ends.
    pub wake_interval: std::time::Duration,
}

/// A token-bucket rate: `per_sec` a second, bursts of `burst`.
#[derive(Debug, Clone, Copy)]
pub struct Rate {
    pub per_sec: f64,
    pub burst: f64,
}

/// The platform's trusted roots; unreadable ones are skipped.
#[cfg(unix)]
fn native_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let found = rustls_native_certs::load_native_certs();
    for c in found.certs {
        let _ = roots.add(c);
    }
    if roots.is_empty() {
        eprintln!("saiife: warning: no trusted root certificates found for the hub");
    }
    roots
}

/// The local server and the optional hub client, until both end.
#[cfg(unix)]
pub async fn run(cfg: LinkConfig) -> Result<(), String> {
    let daemon = Daemon::new(cfg.socket_dir, cfg.daemon_uid);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.port))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:{}: {e}", cfg.port))?;
    let roots = cfg.hub_roots;
    let hub = cfg.hub.map(|url| HubConfig {
        url,
        roots: roots.unwrap_or_else(native_roots),
        connect: None,
        opts: HubOpts::default(),
    });
    // `local::serve` never returns on its own. Both share `daemon`, so its
    // call permits bound the daemon load of the hub and the local server
    // together (local's own cap is open connections, `local::MAX_CONNS`).
    let local = local::serve(listener, daemon.clone(), cfg.port);
    match hub {
        // Either end ends `run`: the hub's result, or the local server
        // (which only stops if its task is dropped).
        Some(h) => tokio::select! {
            r = hub::run(h, daemon) => r,
            () = local => Err("the local server stopped".into()),
        },
        None => {
            local.await;
            Ok(())
        }
    }
}

#[cfg(not(unix))]
pub async fn run(cfg: LinkConfig) -> Result<(), String> {
    let _ = (
        cfg.socket_dir,
        cfg.daemon_uid,
        cfg.port,
        cfg.hub,
        cfg.hub_roots,
    );
    Err(WINDOWS_MSG.into())
}
