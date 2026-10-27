//! One task per connection on the control socket (spec §6.3, §8.7).

use crate::ops::{self, Ctx, Notice};
use saiife_ipc::frame::{body_len, decode, encode_max, FrameError, MAX_ANSWER_FRAME};
use saiife_ipc::msg::{err, ErrorCode, Request, OP_HELLO, PROTO};
use saiife_ipc::peer::peer_cred;
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

enum ReadError {
    /// A malformed frame: answer `bad_frame` and close.
    Bad(FrameError),
    /// EOF mid-frame, an IO error or the frame timeout: just close.
    Gone,
}

/// The next frame, `None` at a clean EOF between frames. No timeout while
/// idle between frames.
async fn read_frame(s: &mut UnixStream) -> Result<Option<Map<String, Value>>, ReadError> {
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

async fn write(s: &mut UnixStream, v: &Value) -> bool {
    write_within(s, v, WRITE_TIMEOUT).await
}

async fn write_within(s: &mut UnixStream, v: &Value, limit: Duration) -> bool {
    let Ok(bytes) = encode_max(v, MAX_ANSWER_FRAME) else {
        return false;
    };
    matches!(timeout(limit, s.write_all(&bytes)).await, Ok(Ok(())))
}

pub async fn connection(mut s: UnixStream, ctx: Arc<Ctx>) {
    let accepted = tokio::time::Instant::now();
    let Ok(peer) = peer_cred(&s) else {
        return;
    };
    // Open-connection caps, before any frame is read: idle connections
    // must not use up the daemon's file descriptors.
    let _slot = match ctx.conns.try_open(peer.uid) {
        Ok(slot) => slot,
        Err(code) => {
            ctx.notice(peer.uid, Notice::Connections);
            let msg = "too many open connections";
            write_within(&mut s, &err(0, code, msg), REFUSE_WRITE_TIMEOUT).await;
            return;
        }
    };
    // The peer's start time, read now (one small `/proc` read): a same-user
    // approval's re-authentication names this process, and polkit and the
    // daemon check it was not replaced by another with the same pid.
    let conn = ops::Conn {
        peer,
        start_time: crate::reauth::start_time_of(ctx.proc.as_ref(), peer.pid),
    };
    let mut greeted = false;
    loop {
        let next = if greeted {
            read_frame(&mut s).await
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
            if !write(&mut s, &ops::hello(req.id)).await {
                return;
            }
            continue;
        }
        let answer = match ctx.limits.try_begin(peer.uid, Instant::now()) {
            Ok(_in_flight) => ops::dispatch_conn(&ctx, &conn, req).await,
            Err(code) => {
                ctx.notice(peer.uid, Notice::Requests);
                err(req.id, code, "too many requests from this uid")
            }
        };
        if !write(&mut s, &answer).await {
            return;
        }
    }
}
