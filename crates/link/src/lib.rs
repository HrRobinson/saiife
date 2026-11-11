//! The Workspace link (plan 29): the user-process half between a browser or
//! phone and saiifed's `link.sock`. The daemon decides; this relays.
#![forbid(unsafe_code)]

mod assets;
pub mod daemon;
#[cfg(unix)]
mod hub;
#[cfg(unix)]
mod local;
mod ws;

pub use daemon::{Daemon, LinkError};

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
    pub url: String,
    pub roots: Option<rustls::RootCertStore>,
}

/// The local server and the optional hub client, until both end.
#[cfg(unix)]
pub async fn run(cfg: LinkConfig) -> Result<(), String> {
    let daemon = Daemon::new(cfg.socket_dir, cfg.daemon_uid);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.port))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:{}: {e}", cfg.port))?;
    let hub = cfg.hub.map(|url| HubConfig {
        url,
        roots: cfg.hub_roots,
    });
    let local = local::serve(listener, daemon.clone(), cfg.port);
    match hub {
        Some(h) => {
            let (a, b) = tokio::join!(local, hub::run(h, daemon));
            a.and(b)
        }
        None => local.await,
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
