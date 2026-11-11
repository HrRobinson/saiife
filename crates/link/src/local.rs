//! The localhost HTTP server for the browser UI (plan 29, Task 7).

use crate::Daemon;

/// Serves the UI on `listener` (bound on 127.0.0.1 only). Filled by Task 7.
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    daemon: Daemon,
    port: u16,
) -> Result<(), String> {
    let _ = (listener, daemon, port);
    Ok(())
}
