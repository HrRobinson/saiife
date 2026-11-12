//! One task per connection on the control socket (spec §6.3, §8.7), and on
//! the Workspace link's `link.sock` (plan 29), which answers other ops.

use crate::hooks::{ConnId, HookTable};
use crate::ops::{self, Ctx, Notice};
use saiife_ipc::frame::{body_len, decode, encode_max, FrameError, MAX_ANSWER_FRAME};
#[cfg(unix)]
use saiife_ipc::msg::OP_BOX_FDS;
use saiife_ipc::msg::{err, ErrorCode, Request, OP_HELLO, PROTO};
use saiife_ipc::peer::PeerCred;
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout;

/// Once a frame's first byte is in, the rest must follow within this.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// An answer the peer does not read within this closes the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The `hello` frame must be complete within this of the accept.
pub const HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// How long a refused connection gets to take its `busy` answer.
const REFUSE_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// Which socket a connection came in on: each answers its own ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// `saiife.sock`: [`ops::dispatch_conn`].
    Control,
    /// `link.sock`: [`crate::workspace_ops::dispatch_link`] only.
    Link,
}

/// The next connection's [`ConnId`].
pub fn next_conn_id() -> ConnId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    ConnId(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Tells the hook table that a connection ended, however it ends.
struct EndsHook<'a>(&'a HookTable, ConnId);

impl Drop for EndsHook<'_> {
    fn drop(&mut self) {
        self.0.ended(self.1);
    }
}

enum ReadError {
    /// A malformed frame: answer `bad_frame` and close.
    Bad(FrameError),
    /// EOF mid-frame, an IO error or the frame timeout: just close.
    Gone,
}

/// The next frame, `None` at a clean EOF between frames. No timeout while
/// idle between frames.
async fn read_frame<S: AsyncRead + Unpin>(
    s: &mut S,
) -> Result<Option<Map<String, Value>>, ReadError> {
    let mut h = [0u8; 4];
    match s.read(&mut h[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(_) => return Err(ReadError::Gone),
    }
    let rest = async {
        s.read_exact(&mut h[1..])
            .await
            .map_err(|_| ReadError::Gone)?;
        let n = body_len(h).map_err(ReadError::Bad)?;
        let mut body = vec![0u8; n];
        s.read_exact(&mut body).await.map_err(|_| ReadError::Gone)?;
        decode(&body).map_err(ReadError::Bad)
    };
    match timeout(FRAME_TIMEOUT, rest).await {
        Ok(r) => r.map(Some),
        Err(_) => Err(ReadError::Gone),
    }
}

async fn write<S: AsyncWrite + Unpin>(s: &mut S, v: &Value) -> bool {
    write_within(s, v, WRITE_TIMEOUT).await
}

async fn write_within<S: AsyncWrite + Unpin>(s: &mut S, v: &Value, limit: Duration) -> bool {
    let Ok(bytes) = encode_max(v, MAX_ANSWER_FRAME) else {
        return false;
    };
    matches!(timeout(limit, s.write_all(&bytes)).await, Ok(Ok(())))
}

#[cfg(unix)]
pub async fn connection(s: UnixStream, ctx: Arc<Ctx>) {
    let Ok(peer) = saiife_ipc::peer::peer_cred(&s) else {
        return;
    };
    serve_peer(s, peer, ctx, Listener::Control).await
}

/// One connection on `link.sock` (plan 29).
#[cfg(unix)]
pub async fn link_connection(s: UnixStream, ctx: Arc<Ctx>) {
    let Ok(peer) = saiife_ipc::peer::peer_cred(&s) else {
        return;
    };
    serve_peer(s, peer, ctx, Listener::Link).await
}

/// Accepts on `link.sock` until the task is aborted, one task per
/// connection.
#[cfg(unix)]
pub async fn serve_link(listener: tokio::net::UnixListener, ctx: Arc<Ctx>) {
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                tokio::spawn(link_connection(s, Arc::clone(&ctx)));
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                eprintln!("saiifed: warning: link.sock accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// A connected instance of the control pipe. Its identity is read first, with nothing read
/// from the client: the pipe's static tracking captured the client's token at open.
///
/// `pipe_peer` impersonates, reads the token and reverts with no yield point, so no other
/// task can run on this thread as the client. Keep it that way: never an `.await` inside
/// it, and it stays a synchronous call here. A failed revert aborts the process.
///
/// A client whose identity cannot be read gets nothing.
#[cfg(windows)]
pub async fn connection(s: NamedPipeServer, ctx: Arc<Ctx>) {
    let Ok(peer) = saiife_ipc::peer::pipe_peer(&s) else {
        return;
    };
    serve_peer(s, peer, ctx, Listener::Control).await
}

/// A connection's stream: a unix socket, or a pipe instance on Windows.
#[cfg(unix)]
type Stream = UnixStream;
#[cfg(windows)]
type Stream = NamedPipeServer;

/// The descriptors that follow a `box.fds` frame (plan 37): exactly one
/// byte is read, so the next frame stays in the stream. `Err` leaves the
/// stream out of step: the connection must close.
#[cfg(unix)]
async fn recv_box_fds(s: &Stream) -> std::io::Result<Vec<std::os::fd::OwnedFd>> {
    use saiife_ipc::fdpass::{recv_fds, MAX_FDS};
    let byte = s.async_io(tokio::io::Interest::READABLE, || recv_fds(s, MAX_FDS));
    match timeout(FRAME_TIMEOUT, byte).await {
        Ok(r) => r,
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

/// Serves one identified peer. The caps are taken before any frame is read: a connection
/// over its uid's cap is closed at once, so it cannot hold a pipe instance or a descriptor.
async fn serve_peer(mut s: Stream, peer: PeerCred, ctx: Arc<Ctx>, listener: Listener) {
    let accepted = tokio::time::Instant::now();
    // A gateway MCP child (decision 12), or in locked mode any process of
    // the daemon's own uid: closed before a byte is read or answered.
    if crate::mcp_gateway::unix_peer_refused(&ctx, &peer) {
        let on = match listener {
            Listener::Control => crate::mcp_gateway::PeerSocket::Control,
            Listener::Link => crate::mcp_gateway::PeerSocket::Link,
        };
        ctx.notice(peer.uid, Notice::McpChildPeer(on));
        return;
    }
    // The personal broker talks to its own uid only (decision 3): any
    // other uid, root included, is closed before a byte is answered.
    if ctx.mode == ops::Mode::Personal && !ctx.peer_is_own(&peer) {
        return;
    }
    // Open-connection caps, before any frame is read: idle connections
    // must not use up the daemon's file descriptors.
    let _slot = match ctx.conns.try_open(peer.uid) {
        Ok(slot) => slot,
        Err(code) => {
            ctx.notice_sid(peer.uid, peer.sid.as_deref(), Notice::Connections);
            let msg = "too many open connections";
            write_within(&mut s, &err(0, code, msg), REFUSE_WRITE_TIMEOUT).await;
            return;
        }
    };
    // Windows: the first sight of a SID asks Windows for its name, off the runtime, and
    // lets `Ctx::name_of` answer for its label. Costs nothing once known.
    if let Some(sid) = peer.sid.clone() {
        let dir = Arc::clone(&ctx.directory);
        let _ = tokio::task::spawn_blocking(move || dir.name_of_sid(&sid)).await;
    }
    // The peer's start time, read now (one small `/proc` read): a same-user
    // approval's re-authentication names this process, and polkit and the
    // daemon check it was not replaced by another with the same pid.
    let conn = ops::Conn::new(
        peer.clone(),
        crate::reauth::start_time_of(ctx.proc.as_ref(), peer.pid),
    );
    let _ends = EndsHook(&ctx.hooks, conn.id);
    let mut greeted = false;
    loop {
        let next = if greeted {
            // A hook connection the hook table closes (its overrun) ends here.
            tokio::select! {
                biased;
                _ = conn.close.notified() => return,
                f = read_frame(&mut s) => f,
            }
        } else {
            // No idle timeout between frames, but the hello must come in time.
            tokio::time::timeout_at(accepted + HELLO_DEADLINE, read_frame(&mut s))
                .await
                .unwrap_or(Err(ReadError::Gone))
        };
        let frame = match next {
            Ok(Some(f)) => f,
            Ok(None) | Err(ReadError::Gone) => return,
            Err(ReadError::Bad(e)) => {
                write(&mut s, &err(0, ErrorCode::BadFrame, &e.to_string())).await;
                return;
            }
        };
        let id_hint = frame.get("id").and_then(Value::as_u64).unwrap_or(0);
        let req = match Request::from_map(frame) {
            Ok(r) => r,
            Err(code) => {
                let msg = "a request needs a u64 id and a string op";
                if !write(&mut s, &err(id_hint, code, msg)).await || !greeted {
                    return;
                }
                continue;
            }
        };
        if !greeted {
            if req.op != OP_HELLO {
                let msg = "the first frame must be hello";
                write(&mut s, &err(req.id, ErrorCode::HelloRequired, msg)).await;
                return;
            }
            if req.args.get("proto").and_then(Value::as_u64) != Some(PROTO) {
                let msg = format!("hello needs proto {PROTO}");
                write(&mut s, &err(req.id, ErrorCode::BadRequest, &msg)).await;
                return;
            }
            greeted = true;
            if !write(&mut s, &ops::hello_in(req.id, ctx.mode.as_str())).await {
                return;
            }
            continue;
        }
        // `box.fds` (plan 37): its byte follows the frame at once and is read
        // now, whatever the answer, so the stream stays in step. A byte that
        // cannot be read (EOF, the frame timeout, another byte, too many
        // descriptors) closes the stash and, once answered, the connection.
        #[cfg(unix)]
        let passed = if listener == Listener::Control && req.op == OP_BOX_FDS {
            match recv_box_fds(&s).await {
                Ok(fds) => Some(fds),
                Err(e) => {
                    drop(conn.take_fds());
                    let msg = format!("box.fds: the descriptors did not come: {e}");
                    write(&mut s, &err(req.id, ErrorCode::BadRequest, &msg)).await;
                    return;
                }
            }
        } else {
            None
        };
        let answer = match ctx.limits.try_begin(peer.uid, Instant::now()) {
            Ok(_in_flight) => match listener {
                #[cfg(unix)]
                Listener::Control if passed.is_some() => {
                    ops::box_fds(&conn, &req, passed.unwrap_or_default())
                }
                Listener::Control => ops::dispatch_conn(&ctx, &conn, req).await,
                Listener::Link => crate::workspace_ops::dispatch_link(&ctx, &conn, req).await,
            },
            Err(code) => {
                // A refused request takes no descriptors: the stash goes too.
                #[cfg(unix)]
                drop(conn.take_fds());
                ctx.notice_sid(peer.uid, peer.sid.as_deref(), Notice::Requests);
                err(req.id, code, "too many requests from this uid")
            }
        };
        if !write(&mut s, &answer).await {
            return;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use saiife_ipc::frame::encode_max;
    use serde_json::json;

    /// Serve one end of a socket pair as `ctx` and send a hello from the
    /// other; what came back before EOF.
    async fn hello_answer_bytes(ctx: Arc<Ctx>) -> Vec<u8> {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(theirs, ctx));
        let hello = json!({"id": 1, "op": OP_HELLO, "proto": PROTO});
        let frame = encode_max(&hello, MAX_ANSWER_FRAME).unwrap();
        // The far end may already be closed: a failed write is fine.
        let _ = ours.write_all(&frame).await;
        let _ = ours.shutdown().await;
        let mut got = Vec::new();
        let read = timeout(Duration::from_secs(5), ours.read_to_end(&mut got)).await;
        assert!(read.is_ok(), "the connection was not closed");
        let _ = task.await;
        got
    }

    /// A greeted connection to `ctx` (as its own uid) and its task.
    async fn greeted(ctx: Arc<Ctx>) -> (UnixStream, tokio::task::JoinHandle<()>) {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(theirs, ctx));
        let hello = json!({"id": 1, "op": OP_HELLO, "proto": PROTO});
        assert_eq!(ask(&mut ours, hello, &[]).await["ok"], true);
        (ours, task)
    }

    /// Sends `req`, then (when `fds` is not empty, or `req` is `box.fds`)
    /// the fd byte with `fds`, and reads one answer.
    async fn ask(s: &mut UnixStream, req: Value, fds: &[std::os::fd::BorrowedFd<'_>]) -> Value {
        s.write_all(&encode_max(&req, MAX_ANSWER_FRAME).unwrap())
            .await
            .unwrap();
        if req["op"] == OP_BOX_FDS {
            saiife_ipc::fdpass::send_fds(&*s, fds).unwrap();
        }
        answer(s).await.expect("an answer")
    }

    /// The next answer frame, `None` at EOF.
    async fn answer(s: &mut UnixStream) -> Option<Value> {
        let mut h = [0u8; 4];
        let read = timeout(Duration::from_secs(5), s.read_exact(&mut h)).await;
        read.expect("answered in time").ok()?;
        let mut body = vec![0u8; saiife_ipc::frame::body_len_max(h, MAX_ANSWER_FRAME).unwrap()];
        s.read_exact(&mut body).await.unwrap();
        Some(serde_json::from_slice(&body).unwrap())
    }

    /// A descriptor to pass, and the far end that tells whether every copy
    /// of it is closed. Only this pair's own state is checked, so tests
    /// opening descriptors in parallel cannot change the answer.
    fn witness() -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        let (pass, far) = std::os::unix::net::UnixStream::pair().unwrap();
        far.set_nonblocking(true).unwrap();
        (pass, far)
    }

    /// Whether every copy of the witness's passed end is closed (EOF).
    fn closed(far: &std::os::unix::net::UnixStream) -> bool {
        use std::io::Read;
        match (&*far).read(&mut [0u8; 1]) {
            Ok(0) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            other => panic!("{other:?}"),
        }
    }

    fn fds_req(id: u64, n: Value) -> Value {
        json!({"id": id, "op": OP_BOX_FDS, "n": n})
    }

    #[tokio::test]
    async fn fds_reach_the_next_op() {
        use std::os::fd::AsFd;
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let (mut ours, task) = greeted(ctx).await;
        std::fs::write(t.path().join("a"), "alpha").unwrap();
        std::fs::write(t.path().join("b"), "beta").unwrap();
        let a = std::fs::File::open(t.path().join("a")).unwrap();
        let b = std::fs::File::open(t.path().join("b")).unwrap();
        let r = ask(&mut ours, fds_req(2, 2.into()), &[a.as_fd(), b.as_fd()]).await;
        assert_eq!(r, json!({"id": 2, "ok": true}));
        let r = ask(&mut ours, json!({"id": 3, "op": ops::TEST_FDS_OP}), &[]).await;
        assert_eq!(r["texts"], json!(["alpha", "beta"]), "{r}");
        // Taken: the next one finds none.
        let r = ask(&mut ours, json!({"id": 4, "op": ops::TEST_FDS_OP}), &[]).await;
        assert_eq!(r["texts"], json!([]), "{r}");
        // Any other op closes what is kept.
        let (pass, far) = witness();
        let r = ask(&mut ours, fds_req(5, 1.into()), &[pass.as_fd()]).await;
        assert_eq!(r["ok"], true, "{r}");
        drop(pass);
        assert!(!closed(&far));
        let r = ask(&mut ours, json!({"id": 6, "op": "status"}), &[]).await;
        assert_eq!(r["ok"], true, "{r}");
        assert!(closed(&far));
        let r = ask(&mut ours, json!({"id": 7, "op": ops::TEST_FDS_OP}), &[]).await;
        assert_eq!(r["texts"], json!([]), "{r}");
        drop(ours);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stash_is_dropped_with_the_connection() {
        use std::os::fd::AsFd;
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let (mut ours, task) = greeted(ctx).await;
        let (pass, far) = witness();
        let r = ask(&mut ours, fds_req(2, 1.into()), &[pass.as_fd()]).await;
        assert_eq!(r["ok"], true, "{r}");
        drop(pass);
        assert!(!closed(&far), "the daemon keeps it");
        drop(ours);
        task.await.unwrap();
        assert!(closed(&far), "closed with the connection");
    }

    #[tokio::test]
    async fn second_box_fds_is_bad_request() {
        use std::os::fd::AsFd;
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let (mut ours, task) = greeted(ctx).await;
        let (p1, f1) = witness();
        let (p2, f2) = witness();
        let r = ask(&mut ours, fds_req(2, 1.into()), &[p1.as_fd()]).await;
        assert_eq!(r["ok"], true, "{r}");
        let r = ask(&mut ours, fds_req(3, 1.into()), &[p2.as_fd()]).await;
        assert_eq!(r["error"], "bad_request", "{r}");
        drop((p1, p2));
        assert!(closed(&f1) && closed(&f2), "both sets are closed");
        // Still in step: the connection answers on.
        let r = ask(&mut ours, json!({"id": 4, "op": ops::TEST_FDS_OP}), &[]).await;
        assert_eq!(r["texts"], json!([]), "{r}");
        drop(ours);
        task.await.unwrap();
    }

    /// A count that is not 1 to MAX_FDS, or not what came, is refused with
    /// every descriptor closed, and the connection answers on.
    #[tokio::test]
    async fn bad_box_fds_counts_are_bad_request() {
        use std::os::fd::AsFd;
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let (mut ours, task) = greeted(ctx).await;
        let (pass, far) = witness();
        let one = [pass.as_fd()];
        let cases: [(Value, &[std::os::fd::BorrowedFd<'_>]); 6] = [
            (0.into(), &[]),
            (1.into(), &[]),
            (0.into(), &one),
            (2.into(), &one),
            (Value::Null, &one),
            ("1".into(), &one),
        ];
        for (i, (n, fds)) in cases.into_iter().enumerate() {
            let r = ask(&mut ours, fds_req(10 + i as u64, n.clone()), fds).await;
            assert_eq!(r["error"], "bad_request", "n {n}: {r}");
        }
        drop(pass);
        assert!(closed(&far));
        let r = ask(&mut ours, json!({"id": 30, "op": "status"}), &[]).await;
        assert_eq!(r["ok"], true, "{r}");
        drop(ours);
        task.await.unwrap();
    }

    /// More than MAX_FDS, or no fd byte after the frame: refused, every
    /// descriptor closed, and the connection closed (out of step).
    #[tokio::test]
    async fn unreadable_box_fds_closes_the_connection() {
        use std::os::fd::AsFd;
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let (mut ours, task) = greeted(Arc::clone(&ctx)).await;
        let pairs: Vec<_> = (0..5).map(|_| witness()).collect();
        let fds: Vec<_> = pairs.iter().map(|(p, _)| p.as_fd()).collect();
        let r = ask(&mut ours, fds_req(2, 5.into()), &fds).await;
        assert_eq!(r["error"], "bad_request", "{r}");
        assert_eq!(answer(&mut ours).await, None, "closed");
        task.await.unwrap();
        drop(fds);
        for (p, far) in pairs {
            drop(p);
            assert!(closed(&far));
        }
        // A request where the byte should be.
        let (mut ours, task) = greeted(ctx).await;
        let mut two = encode_max(&fds_req(2, 1.into()), MAX_ANSWER_FRAME).unwrap();
        two.extend(encode_max(&json!({"id": 3, "op": "status"}), MAX_ANSWER_FRAME).unwrap());
        ours.write_all(&two).await.unwrap();
        let r = answer(&mut ours).await.unwrap();
        assert_eq!(r["error"], "bad_request", "{r}");
        assert_eq!(answer(&mut ours).await, None, "closed");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn foreign_uid_closed_before_hello() {
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me.wrapping_add(1));
        assert!(hello_answer_bytes(ctx).await.is_empty());
        // The same pair as the own uid gets its hello answer.
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        let got = hello_answer_bytes(ctx).await;
        assert!(got.len() > 4);
        let body: Value = serde_json::from_slice(&got[4..]).unwrap();
        assert_eq!(body["mode"], "personal", "{body}");
    }

    #[tokio::test]
    async fn locked_ctx_still_answers_other_uids() {
        // The locked daemon decides per op, not at the accept.
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, me.wrapping_add(1));
        let got = hello_answer_bytes(ctx).await;
        assert!(got.len() > 4);
        let body: Value = serde_json::from_slice(&got[4..]).unwrap();
        assert_eq!(body["mode"], "locked", "{body}");
    }

    /// A gateway MCP child (here: this test process, counted as one) is
    /// closed before its hello, in both modes; the pid check is all the
    /// personal broker has, since its clients share its uid.
    /// Linux only: no gateway children elsewhere (plan 13, decision 7).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mcp_child_peer_closed_before_hello() {
        let me = rustix::process::getuid().as_raw();
        for mode in [ops::Mode::Personal, ops::Mode::Locked] {
            let t = tempfile::tempdir().unwrap();
            let (ctx, _join) = ops::test_ctx(t.path(), mode, me);
            ctx.mcp.add_test_pid(std::process::id());
            assert!(hello_answer_bytes(ctx).await.is_empty(), "{mode:?}");
        }
    }

    /// The same refusal on `link.sock` is recorded as the link socket's
    /// (plan 29), not the control socket's.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mcp_child_peer_on_link_sock_is_labelled_link() {
        let me = rustix::process::getuid().as_raw();
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Personal, me);
        ctx.mcp.add_test_pid(std::process::id());
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let task = tokio::spawn(link_connection(theirs, ctx));
        let _ = ours.shutdown().await;
        let mut got = Vec::new();
        let read = timeout(Duration::from_secs(5), ours.read_to_end(&mut got)).await;
        assert!(read.is_ok(), "the connection was not closed");
        assert!(got.is_empty(), "{got:?}");
        let _ = task.await;
        let why = Notice::McpChildPeer(crate::mcp_gateway::PeerSocket::Link).reason(me);
        assert!(why.starts_with("the link socket closed"), "{why}");
    }

    /// Locked mode, refusing its own uid (as the daemon's start sets it):
    /// a peer of the daemon's uid is closed before hello; another uid is
    /// answered.
    #[tokio::test]
    async fn locked_own_uid_peer_closed_before_hello() {
        let me = rustix::process::getuid().as_raw();
        let t = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, me);
        Arc::get_mut(&mut ctx).unwrap().refuse_own_uid_peers = true;
        assert!(hello_answer_bytes(ctx).await.is_empty());
        let t = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, me.wrapping_add(1));
        Arc::get_mut(&mut ctx).unwrap().refuse_own_uid_peers = true;
        assert!(hello_answer_bytes(ctx).await.len() > 4);
    }

    /// A hook connection with no verdict by `HOOK_OVERRUN` is closed by the
    /// daemon and recorded; a CLI connection idles on.
    #[tokio::test(start_paused = true)]
    async fn overrun_is_closed_and_recorded() {
        let t = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, me);
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let (mut cli, cli_theirs) = UnixStream::pair().unwrap();
        let task = tokio::spawn(connection(theirs, Arc::clone(&ctx)));
        let cli_task = tokio::spawn(connection(cli_theirs, Arc::clone(&ctx)));
        let start = tokio::time::Instant::now();
        for (n, op) in [(1, json!({"op": OP_HELLO, "proto": PROTO}))]
            .into_iter()
            .chain([(
                2,
                json!({"op": saiife_ipc::msg::OP_HOOK_BEGIN, "agent": "claude"}),
            )])
        {
            let mut m = op;
            m["id"] = n.into();
            ours.write_all(&encode_max(&m, MAX_ANSWER_FRAME).unwrap())
                .await
                .unwrap();
        }
        let hello = json!({"id": 1, "op": OP_HELLO, "proto": PROTO});
        cli.write_all(&encode_max(&hello, MAX_ANSWER_FRAME).unwrap())
            .await
            .unwrap();
        // Both answers: the begin is in.
        let mut answers = vec![0u8; 4 + 61 + 4 + 18];
        ours.read_exact(&mut answers).await.unwrap();
        assert!(answers.ends_with(br#"{"id":2,"ok":true}"#), "{answers:?}");
        // The paused clock may run ahead while the socket is idle, so the
        // overrun's exact time is the hook table's test; here: closed, and
        // recorded, no earlier than the overrun.
        // Then EOF from the daemon's side.
        let mut got = Vec::new();
        let read = timeout(Duration::from_secs(60), ours.read_to_end(&mut got)).await;
        assert!(read.is_ok(), "the hook connection was not closed");
        assert!(got.is_empty(), "{got:?}");
        assert!(start.elapsed() >= crate::hooks::HOOK_OVERRUN);
        let _ = task.await;
        assert_eq!(ctx.hooks.no_verdict_count().0, 1);
        // The CLI connection is still open.
        assert!(!cli_task.is_finished());
        cli_task.abort();
    }

    fn windows_peer(uid: u32, sid: &str) -> PeerCred {
        PeerCred {
            uid,
            gid: 0,
            pid: std::process::id(),
            sid: Some(sid.to_string()),
            group_sids: Vec::new(),
        }
    }

    /// `serve_peer` over a socket pair, as a Windows pipe peer: what came back.
    async fn peer_answer(ctx: Arc<Ctx>, peer: PeerCred) -> Vec<u8> {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_peer(theirs, peer, ctx, Listener::Control));
        let hello = json!({"id": 1, "op": OP_HELLO, "proto": PROTO});
        let _ = ours
            .write_all(&encode_max(&hello, MAX_ANSWER_FRAME).unwrap())
            .await;
        let _ = ours.shutdown().await;
        let mut got = Vec::new();
        let read = timeout(Duration::from_secs(5), ours.read_to_end(&mut got)).await;
        assert!(read.is_ok(), "the connection was not closed");
        let _ = task.await;
        got
    }

    const OWN: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    /// The SID is the identity: a stranger with the daemon's uid label is no own-uid peer,
    /// and the daemon's own SID is, whatever its label.
    #[tokio::test]
    async fn own_peer_is_decided_on_the_sid() {
        let t = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, 7);
        {
            let c = Arc::get_mut(&mut ctx).unwrap();
            c.refuse_own_uid_peers = true;
            c.own_sid = Some(OWN.to_string());
        }
        assert!(
            peer_answer(Arc::clone(&ctx), windows_peer(7, OTHER))
                .await
                .len()
                > 4
        );
        assert!(peer_answer(ctx, windows_peer(9, OWN)).await.is_empty());
    }

    /// The per-uid cap holds before a frame is read: one over gets `busy` and is closed,
    /// and another uid still gets in.
    #[tokio::test]
    async fn over_the_uid_cap_is_refused_at_accept() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = ops::test_ctx(t.path(), ops::Mode::Locked, 7);
        let held: Vec<_> = (0..crate::limits::MAX_CONNS_PER_UID)
            .map(|_| ctx.conns.try_open(1000).unwrap())
            .collect();
        let got = peer_answer(Arc::clone(&ctx), windows_peer(1000, OTHER)).await;
        let body: Value = serde_json::from_slice(&got[4..]).unwrap();
        assert_eq!(body["error"], "busy", "{body}");
        assert!(
            peer_answer(Arc::clone(&ctx), windows_peer(1001, OWN))
                .await
                .len()
                > 4
        );
        drop(held);
    }
}
