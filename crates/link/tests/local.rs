//! The localhost server over real loopback TCP, against an in-process daemon.
#![cfg(unix)]

mod common;

use common::http::{frame_for, json_of, Server};
use common::{control, me, scratch, world, World};
use http::StatusCode;
use saiife_ipc::msg::{OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM};
use saiife_link::assets::{etag, ASSETS};
use saiife_link::local::{serve_with, Opts, CSP, MAX_REQUEST_BYTES};
use saiife_link::Daemon;
use saiife_wire::sig::TestDevice;
use saiife_wire::{b64, pair};
use serde_json::json;

async fn up() -> (World, Server) {
    let w = world().await;
    let s = Server::start(Daemon::new(w.run.clone(), me())).await;
    (w, s)
}

#[tokio::test]
async fn index_has_csp_and_nosniff() {
    let (_w, s) = up().await;
    for path in ["/", "/index.html", "/app.css"] {
        let (st, h, body) = s.get(path).await;
        assert_eq!(st, StatusCode::OK, "{path}");
        assert_eq!(h["content-security-policy"], CSP);
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cross-origin-opener-policy"], "same-origin");
        assert_eq!(h["cross-origin-resource-policy"], "same-origin");
        assert_eq!(
            h["permissions-policy"],
            "camera=(), microphone=(), geolocation=()"
        );
        assert_eq!(h["cache-control"], "no-cache");
        assert!(h.contains_key("etag") && h.contains_key("content-type"));
        assert!(!body.is_empty());
    }
    let (_, _, body) = s.get("/").await;
    assert!(String::from_utf8_lossy(&body).contains("saiife Workspace"));
}

#[tokio::test]
async fn etag_304() {
    let (_w, s) = up().await;
    let (_, h, _) = s.get("/app.css").await;
    let tag = h["etag"].to_str().unwrap().to_string();
    let a = ASSETS.iter().find(|a| a.path == "/app.css").unwrap();
    assert_eq!(tag, etag(a));
    assert_eq!(tag.len(), 18);
    let host = s.host();
    let (st, h, body) = s
        .send(
            "GET",
            "/app.css",
            &[("host", &host), ("if-none-match", &tag)],
            Vec::new(),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(h["etag"], tag.as_str());
    assert_eq!(h["content-security-policy"], CSP);
    let (st, _, _) = s
        .send(
            "GET",
            "/app.css",
            &[("host", &host), ("if-none-match", "\"0000000000000000\"")],
            Vec::new(),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn rebinding_host_is_refused() {
    let (_w, s) = up().await;
    let port = s.addr.port();
    for host in [
        format!("evil.test:{port}"),
        format!("127.0.0.1:{port}"),
        "localhost".to_string(),
        format!("localhost:{}", port.wrapping_add(1)),
    ] {
        for path in ["/", "/api/hello"] {
            let (st, h, _) = s.send("GET", path, &[("host", &host)], Vec::new()).await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{host} {path}");
            assert_eq!(h["content-security-policy"], CSP);
        }
    }
    // No Host header at all (HTTP/1.1 without one).
    let (st, _, _) = s.send("GET", "/", &[], Vec::new()).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cross_origin_post_is_refused() {
    let (_w, s) = up().await;
    let host = s.host();
    let body = serde_json::to_vec(&json!({"body": "x", "sig": "y"})).unwrap();
    let ct = ("content-type", "application/json");
    for origin in [
        Some("https://evil.test"),
        Some("http://127.0.0.1"),
        Some("null"),
        None,
    ] {
        let mut hs = vec![("host", host.as_str()), ct];
        if let Some(o) = origin {
            hs.push(("origin", o));
        }
        let (st, _, _) = s.send("POST", "/api/frame", &hs, body.clone()).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{origin:?}");
    }
    // The port is part of the origin.
    let wrong = format!("http://localhost:{}", s.addr.port().wrapping_add(1));
    let hs = [("host", host.as_str()), ct, ("origin", wrong.as_str())];
    let (st, _, _) = s.send("POST", "/api/pair", &hs, body).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wrong_content_type_is_415() {
    let (_w, s) = up().await;
    let (host, origin) = (s.host(), s.origin());
    let body = serde_json::to_vec(&json!({"body": "x", "sig": "y"})).unwrap();
    for ct in [
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
        Some("application/jsonp"),
        Some("application/json; charset=latin1"),
        None,
    ] {
        let mut hs = vec![("host", host.as_str()), ("origin", origin.as_str())];
        if let Some(c) = ct {
            hs.push(("content-type", c));
        }
        let (st, _, _) = s.send("POST", "/api/frame", &hs, body.clone()).await;
        assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{ct:?}");
    }
    // The accepted spellings reach the daemon check (400: not a frame).
    for ct in ["application/json", "Application/JSON; charset=UTF-8"] {
        let hs = [
            ("host", host.as_str()),
            ("origin", origin.as_str()),
            ("content-type", ct),
        ];
        let (st, _, _) = s.send("POST", "/api/frame", &hs, b"[]".to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{ct}");
    }
}

#[tokio::test]
async fn oversize_post_is_413() {
    let (_w, s) = up().await;
    let big = "a".repeat(MAX_REQUEST_BYTES + 1);
    let (st, _, _) = s
        .post("/api/frame", &json!({"body": big, "sig": "y"}))
        .await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    // Right at the limit is read (and refused for what it is, not its size).
    let pad = "a".repeat(MAX_REQUEST_BYTES - 40);
    let (st, _, _) = s
        .post("/api/frame", &json!({"body": pad, "sig": "y"}))
        .await;
    assert_ne!(st, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn body_without_length_is_capped_while_read() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_w, s) = up().await;
    let mut c = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    // Chunked: no Content-Length to check up front; 4 x 32 KiB > the cap.
    let head = format!(
        "POST /api/frame HTTP/1.1\r\nhost: {}\r\norigin: {}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n",
        s.host(),
        s.origin()
    );
    c.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![b'a'; 32 * 1024];
    for _ in 0..4 {
        // The server may answer and close before the last chunk; ignore that.
        let _ = c
            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
            .await;
        let _ = c.write_all(&chunk).await;
        let _ = c.write_all(b"\r\n").await;
    }
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 413"), "{text:.200}");
}

/// Pairs a device: begin and confirm on the control side, finish over
/// `POST /api/pair`.
async fn paired(w: &World, s: &Server) -> TestDevice {
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "laptop"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let (st, _, body) = s
        .post(
            "/api/pair",
            &json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pubkey),
                "label": "phone",
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pubkey)),
            }),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a.as_object().unwrap().len(), 2, "{a}");
    let f = &a["result"];
    assert_eq!(f["device_id"], d.device_id(), "{a}");
    assert_eq!(f["short_code"].as_str().unwrap().len(), 7, "{a}");
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": pair_id, "accept": true}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
    d
}

#[tokio::test]
async fn frame_passes_through() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let sf = frame_for(&w, &d, "box.overview");
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["boxes"].as_array().unwrap().len(), 4, "{a}");
}

#[tokio::test]
async fn frame_envelope_is_strict() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let sf = frame_for(&w, &d, "box.overview");
    // Keys the browser may not set (the daemon refuses channel_device for
    // via=local, and via is ours), a missing key, a non-string.
    for v in [
        json!({"body": sf.body, "sig": sf.sig, "via": "hub"}),
        json!({"body": sf.body, "sig": sf.sig, "channel_device": "x"}),
        json!({"body": sf.body}),
        json!({"body": 1, "sig": sf.sig}),
    ] {
        let (st, _, _) = s.post("/api/frame", &v).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    }
    let (st, _, _) = s
        .post("/api/pair", &json!({"pair_id": "a", "extra": "b"}))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Nothing above reached the daemon: the frame still verifies once.
    let (_, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(json_of(&body)["ok"], true);
}

#[tokio::test]
async fn refusal_keeps_rule() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let sf = frame_for(&w, &d, "box.land");
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    assert!(a["error"].is_string() && a["message"].is_string(), "{a}");
}

#[tokio::test]
async fn hello_and_pair_refusals() {
    let (_w, s) = up().await;
    let (st, _, body) = s.get("/api/hello").await;
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a.as_object().unwrap().len(), 2, "{a}");
    let h = &a["result"];
    assert!(
        h["machine_id"].as_str().is_some_and(|m| !m.is_empty()),
        "{a}"
    );
    assert!(h.get("ok").is_none() && h.get("id").is_none(), "{a}");
    // A pair that was never begun: the daemon's refusal, as 200 ok:false.
    let (st, _, body) = s
        .post(
            "/api/pair",
            &json!({"pair_id": "nope", "device_pub": "AAAA", "label": "x", "proof": "AAAA"}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(a["ok"], false, "{a}");
    assert!(a.get("rule").is_some() && a["error"].is_string(), "{a}");
    assert!(a["message"].is_string(), "{a}");
}

#[tokio::test]
async fn daemon_down_is_503() {
    let tmp = scratch();
    let s = Server::start(Daemon::new(tmp.path().to_path_buf(), me())).await;
    let (st, h, body) = s.get("/api/hello").await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(h["content-security-policy"], CSP);
    let a = json_of(&body);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "unreachable", "{a}");
    // `rule` is always present: null when the daemon did not answer.
    assert!(a["rule"].is_null() && a.get("rule").is_some(), "{a}");
    let (st, _, _) = s
        .post("/api/frame", &json!({"body": "x", "sig": "y"}))
        .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn unknown_path_is_404() {
    let (_w, s) = up().await;
    for path in [
        "/nope",
        "/api",
        "/api/other",
        "/api/frame/",
        "/index.html/x",
    ] {
        let (st, h, _) = s.get(path).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(h["content-security-policy"], CSP);
    }
    // A method the route does not take.
    let (st, _, _) = s.get("/api/frame").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = s.post("/api/hello", &json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = s.post("/api/elsewhere", &json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn trickled_body_times_out_408() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let w = world().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let opts = Opts {
        body_read_timeout: std::time::Duration::from_millis(300),
        ..Opts::default()
    };
    tokio::spawn(serve_with(
        l,
        Daemon::new(w.run.clone(), me()),
        addr.port(),
        opts,
    ));
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /api/frame HTTP/1.1\r\nhost: localhost:{p}\r\norigin: http://localhost:{p}\r\ncontent-type: application/json\r\ncontent-length: 5000\r\n\r\n{{\"body\"",
        p = addr.port()
    );
    c.write_all(head.as_bytes()).await.unwrap();
    // ... and then nothing.
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut out))
        .await
        .expect("the server answers or closes");
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 408"),
        "{:.200}",
        String::from_utf8_lossy(&out)
    );
}

#[tokio::test]
async fn connections_over_the_cap_are_closed() {
    use tokio::io::AsyncReadExt;
    let w = world().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let opts = Opts {
        max_conns: 1,
        ..Opts::default()
    };
    tokio::spawn(serve_with(
        l,
        Daemon::new(w.run.clone(), me()),
        addr.port(),
        opts,
    ));
    // The first connection is idle and holds the only slot.
    let _first = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = Vec::new();
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        second.read_to_end(&mut buf),
    )
    .await
    .expect("closed promptly")
    .unwrap_or(0);
    assert_eq!(n, 0);
}

#[tokio::test]
async fn charset_without_space_is_accepted() {
    let (_w, s) = up().await;
    let (h, o) = (s.host(), s.origin());
    let hs = [
        ("host", h.as_str()),
        ("origin", o.as_str()),
        ("content-type", "application/json;charset=utf-8"),
    ];
    let (st, _, _) = s.send("POST", "/api/frame", &hs, b"[]".to_vec()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}
