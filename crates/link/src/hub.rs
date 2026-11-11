//! The hub client: connect, reconnect, relay (plan 29, Task 9).

use crate::{Daemon, HubConfig};

/// Connects to the hub and relays. Filled by Task 9.
pub(crate) async fn run(cfg: HubConfig, daemon: Daemon) -> Result<(), String> {
    let _ = (cfg.url, cfg.roots, daemon);
    Ok(())
}
