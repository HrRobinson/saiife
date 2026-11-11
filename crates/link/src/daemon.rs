//! The client of `link.sock`: one blocking `saiife_ipc` connection per call,
//! made inside `spawn_blocking`. The daemon decides everything; this only
//! relays and keeps the daemon's refusal (`error`, `rule`, `message`).

#[cfg(unix)]
use saiife_ipc::client::{Client, ClientError};
#[cfg(unix)]
use saiife_ipc::msg::LINK_SOCKET_NAME;
use serde_json::{Map, Value};
use std::path::PathBuf;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// No daemon answered in time, or the exchange broke.
    Unreachable(String),
    /// The daemon answered `ok: false`.
    Refused {
        error: String,
        rule: Option<String>,
        message: String,
    },
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Unreachable(m) => write!(f, "daemon unreachable: {m}"),
            LinkError::Refused { error, message, .. } => {
                write!(f, "daemon refused ({error}): {message}")
            }
        }
    }
}

impl std::error::Error for LinkError {}

#[derive(Clone)]
pub struct Daemon {
    socket_dir: PathBuf,
    uid: u32,
}

impl Daemon {
    pub fn new(socket_dir: PathBuf, uid: u32) -> Daemon {
        Daemon { socket_dir, uid }
    }

    pub async fn call(
        &self,
        op: &'static str,
        args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.call_blocking(op, args))
            .await
            .map_err(|e| LinkError::Unreachable(format!("call task: {e}")))?
    }

    #[cfg(unix)]
    fn call_blocking(
        &self,
        op: &str,
        args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let unreachable = |e: ClientError| LinkError::Unreachable(e.to_string());
        let mut c = Client::connect_named(
            &self.socket_dir,
            LINK_SOCKET_NAME,
            self.uid,
            Instant::now() + CONNECT_TIMEOUT,
        )
        .map_err(unreachable)?;
        // `call_answer` hands back an `ok: false` answer whole, so `rule` survives.
        let ans = c
            .call_answer(op, args, Instant::now() + CALL_TIMEOUT)
            .map_err(unreachable)?;
        if ans.get("ok").and_then(Value::as_bool) == Some(false) {
            let s = |k: &str| ans.get(k).and_then(Value::as_str).map(str::to_string);
            return Err(LinkError::Refused {
                error: s("error").unwrap_or_default(),
                rule: s("rule"),
                message: s("message").unwrap_or_default(),
            });
        }
        Ok(ans)
    }

    #[cfg(not(unix))]
    fn call_blocking(
        &self,
        _op: &str,
        _args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let _ = (&self.socket_dir, self.uid);
        Err(LinkError::Unreachable(crate::WINDOWS_MSG.into()))
    }
}
