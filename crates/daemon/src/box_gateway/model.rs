//! The model route on a box's `vsock.sock_5002`. Plan 40 fills it in; until
//! then every connection gets a `503` and is closed. Nothing the guest sends
//! is read.

use super::{BoxRun, GatewayShared, Slot};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

const BODY: &str = "model access is not set up yet";

pub(crate) async fn serve_run(mut stream: UnixStream, run: Arc<BoxRun>, gw: Arc<GatewayShared>) {
    // Counted with the box's other connections.
    let Some(_slot) = Slot::take(&run, gw.limits.tunnels) else {
        return;
    };
    let text = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(text.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}
