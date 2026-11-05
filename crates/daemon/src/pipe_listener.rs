//! The control pipe's accept loop (W11): one free instance always ahead of the connected
//! ones, so a client never finds the name gone while the daemon runs.

use saiife_win::ffi::pipe::create_server;
use saiife_win::pipe::{later_instance, LaterInstance};
use std::io;
use std::time::Duration;
use tokio::net::windows::named_pipe::NamedPipeServer;

/// How often a full pipe is tried again.
const FULL_RETRY: Duration = Duration::from_millis(50);

pub struct PipeListener {
    name: String,
    sddl: String,
    /// `None` while the pipe was full when the next instance was due.
    free: Option<NamedPipeServer>,
}

impl PipeListener {
    /// The first instance. A name someone else holds is `ErrorKind::AlreadyExists`, with
    /// W11's line as its text.
    pub fn bind(name: &str, sddl: &str) -> io::Result<PipeListener> {
        Ok(PipeListener {
            free: Some(create_server(name, sddl, true)?),
            name: name.to_string(),
            sddl: sddl.to_string(),
        })
    }

    /// A later instance, or `None` when the pipe is full for now.
    fn next_instance(&self) -> io::Result<Option<NamedPipeServer>> {
        match create_server(&self.name, &self.sddl, false) {
            Ok(i) => Ok(Some(i)),
            Err(e) => match later_instance(&self.name, e) {
                LaterInstance::Full => Ok(None),
                LaterInstance::Failed(e) => Err(e),
            },
        }
    }

    /// The next connected client. Cancel safe: `connect` loses no connection when
    /// dropped, and nothing here awaits after it completes. An `AlreadyExists` error
    /// means the name is someone else's now, and the daemon must not go on serving.
    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        loop {
            if self.free.is_none() {
                self.free = self.next_instance()?;
            }
            let Some(free) = &self.free else {
                // Every instance is connected. Each uid holds at most its cap of them, so
                // this ends as connections close; clients retry `ERROR_PIPE_BUSY` meanwhile.
                tokio::time::sleep(FULL_RETRY).await;
                continue;
            };
            if let Err(e) = free.connect().await {
                // A client that came and went leaves this instance unusable.
                self.free = None;
                return Err(e);
            }
            let connected = self.free.take();
            // The next one before handling this one. A full pipe is not an error: this
            // client is served, and the loop above tries again.
            self.free = self.next_instance()?;
            if let Some(c) = connected {
                return Ok(c);
            }
        }
    }

    /// Stops accepting: the free instance goes.
    pub fn close(&mut self) {
        self.free = None;
    }
}
