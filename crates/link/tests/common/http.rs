//! The localhost server on 127.0.0.1:0 and a one-shot HTTP client for it,
//! plus frames signed by a `TestDevice` (shared by local.rs and ui_flows.rs).

use super::World;
use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use saiife_link::local::serve;
use saiife_link::Daemon;
use saiife_wire::b64;
use saiife_wire::frame::{Frame, SignedFrame};
use saiife_wire::sig::TestDevice;
use serde_json::{Map, Value};
use std::net::SocketAddr;

pub struct Server {
    pub addr: SocketAddr,
}

impl Server {
    pub async fn start(daemon: Daemon) -> Server {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(l, daemon, addr.port()));
        Server { addr }
    }

    pub fn host(&self) -> String {
        format!("localhost:{}", self.addr.port())
    }

    pub fn origin(&self) -> String {
        format!("http://localhost:{}", self.addr.port())
    }

    /// One request on a fresh connection; `headers` are sent as given.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let s = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut b = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let r = tx.send_request(b.body(Full::new(Bytes::from(body))).unwrap());
        let resp = r.await.unwrap();
        let (parts, body) = resp.into_parts();
        (
            parts.status,
            parts.headers,
            body.collect().await.unwrap().to_bytes(),
        )
    }

    pub async fn get(&self, path: &str) -> (StatusCode, HeaderMap, Bytes) {
        let h = self.host();
        self.send("GET", path, &[("host", &h)], Vec::new()).await
    }

    /// A POST as the page sends it: same origin, `application/json`.
    pub async fn post(&self, path: &str, v: &Value) -> (StatusCode, HeaderMap, Bytes) {
        let (h, o) = (self.host(), self.origin());
        self.send(
            "POST",
            path,
            &[
                ("host", &h),
                ("origin", &o),
                ("content-type", "application/json"),
            ],
            serde_json::to_vec(v).unwrap(),
        )
        .await
    }
}

pub fn json_of(b: &Bytes) -> Value {
    serde_json::from_slice(b).unwrap_or_else(|e| panic!("{e}: {b:?}"))
}

/// A frame for the daemon's current hello, a fresh nonce, a 60 s TTL.
pub fn frame_with(
    w: &World,
    d: &TestDevice,
    action: &str,
    args: Map<String, Value>,
) -> SignedFrame {
    let h = w.ctx.workspace.hello();
    let now = saiife_daemon::workspace::now_secs();
    let mut n = [0u8; 16];
    getrandom::fill(&mut n).unwrap();
    d.frame(&Frame {
        v: 1,
        machine_id: h["machine_id"].as_str().unwrap().into(),
        epoch: h["epoch"].as_str().unwrap().into(),
        device_id: d.device_id(),
        action: action.into(),
        args,
        nonce: b64::enc(&n),
        issued_at: now,
        expires_at: now + 60,
    })
}

pub fn frame_for(w: &World, d: &TestDevice, action: &str) -> SignedFrame {
    frame_with(w, d, action, Map::new())
}
