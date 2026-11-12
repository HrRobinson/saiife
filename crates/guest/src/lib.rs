//! The guest agent that runs inside the box VM. Tokio-free by design; Linux in
//! practice, but every module compiles on all targets.
#![forbid(unsafe_code)]

pub mod control;
pub mod env;
pub mod events;
pub mod export;
pub mod pty;
pub mod setup;

pub use env::{GuestEnv, GuestTools, Timing};
pub use saiife_boxproto::msg::Event;

/// The service main (`saiife __guest init`). Returns only on a fatal error;
/// systemd restarts it.
///
/// A restarted init (the setup marker exists but this process never spawned
/// an agent) hellos `set_up: true`, so the host does not set the box up again,
/// and then reports `Exited { code: None }` first: the earlier agent died with
/// the earlier process (its PTY master was that process's). A re-hello within
/// one process (the events link dropped and came back) reports nothing extra.
pub fn run_init(env: &GuestEnv) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return control::run(env);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = env;
        Err("saiife-guest runs only inside the Linux box VM".into())
    }
}

/// `saiife __guest event turn-finished`: one event to local.sock.
pub fn send_local_event(env: &GuestEnv, ev: &Event) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return control::send_local(env, ev);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (env, ev);
        Err("saiife-guest runs only inside the Linux box VM".into())
    }
}
