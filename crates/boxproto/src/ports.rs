//! The fixed ports, sockets and timings of the box guest channel.

/// vsock port the guest connects to for events (guest to host).
pub const EVENTS: u32 = 5000;
/// vsock port for the egress proxy (guest to host).
pub const EGRESS: u32 = 5001;
/// vsock port for the model route (guest to host).
pub const MODEL: u32 = 5002;
/// vsock port the guest connects to for the terminal stream (guest to host).
pub const PTY: u32 = 5003;
/// vsock port the guest listens on for host requests (host to guest).
pub const CONTROL: u32 = 1024;
/// The guest-to-host ports the host binds a listener for.
pub const ALL_HOST_PORTS: [u32; 4] = [EVENTS, EGRESS, MODEL, PTY];

/// Guest TCP port of the egress proxy (binds 0.0.0.0).
pub const PROXY_TCP: u16 = 3128;
/// Guest TCP port of the model route (binds 127.0.0.1).
pub const MODEL_TCP: u16 = 3129;

/// Directory of the guest sockets (mode 0755).
pub const GUEST_SOCK_DIR: &str = "/run/saiife-guest";
/// Guest events socket.
pub const GUEST_EVENTS_SOCK: &str = "/run/saiife-guest/events.sock";
/// Guest terminal socket.
pub const GUEST_PTY_SOCK: &str = "/run/saiife-guest/pty.sock";
/// Guest control socket.
pub const GUEST_CONTROL_SOCK: &str = "/run/saiife-guest/control.sock";
/// Guest local socket (mode 0666) for in-guest helpers.
pub const GUEST_LOCAL_SOCK: &str = "/run/saiife-guest/local.sock";

/// Overall deadline of the multiplexer handshake (`CONNECT <port>\n` then `OK <n>\n`), seconds.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 2;
/// How many times the guest tries its hello.
pub const HELLO_TRIES: u32 = 30;
/// Pause between hello tries, seconds.
pub const HELLO_RETRY_SECS: u64 = 1;
