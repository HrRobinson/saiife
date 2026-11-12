//! Cloud Hypervisor REST API client over its Unix socket (std only).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pause,
    Resume,
    PowerButton,
    Snapshot,
    ShutdownVmm,
}

impl Action {
    pub fn path(self) -> &'static str {
        match self {
            Action::Pause => "/api/v1/vm.pause",
            Action::Resume => "/api/v1/vm.resume",
            Action::PowerButton => "/api/v1/vm.power-button",
            Action::Snapshot => "/api/v1/vm.snapshot",
            Action::ShutdownVmm => "/api/v1/vmm.shutdown",
        }
    }
}

/// The `state` field of `vm.info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Paused,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    NoSocket,
    Timeout,
    Http { status: u16, body: String },
    Bad(String),
}

pub struct Api {
    sock: PathBuf,
}

/// A parsed HTTP response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub body: String,
}

pub(crate) fn request_bytes(method: &str, path: &str, body: Option<&str>) -> Vec<u8> {
    let body = body.unwrap_or("");
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn io_err(e: &std::io::Error) -> ApiError {
    use std::io::ErrorKind::*;
    match e.kind() {
        WouldBlock | TimedOut => ApiError::Timeout,
        NotFound | ConnectionRefused => ApiError::NoSocket,
        _ => ApiError::Bad(e.to_string()),
    }
}

/// Read one line byte-wise, never taking more than `*budget` bytes from `r`.
fn read_line_capped<R: Read>(r: &mut R, budget: &mut usize) -> Result<Vec<u8>, ApiError> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if *budget == 0 {
            return Err(ApiError::Bad("response headers too large".into()));
        }
        match r.read(&mut b) {
            Ok(0) => return Err(ApiError::Bad("truncated headers".into())),
            Ok(_) => {
                *budget -= 1;
                if b[0] == b'\n' {
                    return Ok(line);
                }
                line.push(b[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_err(&e)),
        }
    }
}

/// Parse one HTTP/1.1 response. Every read is bounded before it happens:
/// headers take at most `MAX_HEADER_BYTES` bytes and `MAX_HEADER_LINES`
/// lines, the body at most `MAX_BODY` (64 KiB). Transfer-Encoding and
/// conflicting Content-Length headers are refused; 1xx/204/304 have no body.
pub(crate) fn parse_response<R: Read>(mut r: R) -> Result<Response, ApiError> {
    let mut budget = MAX_HEADER_BYTES;
    let mut status = None;
    let mut length: Option<usize> = None;
    let mut lines = 0usize;
    loop {
        let raw = read_line_capped(&mut r, &mut budget)?;
        lines += 1;
        if lines > MAX_HEADER_LINES {
            return Err(ApiError::Bad("response headers too large".into()));
        }
        let t = String::from_utf8_lossy(&raw);
        let t = t.trim_end_matches('\r');
        if status.is_none() {
            let mut parts = t.split_whitespace();
            let ok = parts.next().is_some_and(|v| v.starts_with("HTTP/1."));
            status = parts.next().and_then(|c| c.parse::<u16>().ok());
            if !ok || status.is_none() {
                return Err(ApiError::Bad(format!("bad status line: {t}")));
            }
        } else if t.is_empty() {
            break;
        } else if let Some((k, v)) = t.split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding") {
                return Err(ApiError::Bad("transfer-encoding not supported".into()));
            }
            if k.eq_ignore_ascii_case("content-length") {
                let n: usize = v
                    .trim()
                    .parse()
                    .map_err(|_| ApiError::Bad("bad content-length".into()))?;
                if length.is_some_and(|old| old != n) {
                    return Err(ApiError::Bad("conflicting content-length".into()));
                }
                length = Some(n);
            }
        }
    }
    let status = status.unwrap_or(0);
    let mut body = Vec::new();
    if status < 200 || status == 204 || status == 304 {
        // bodyless by definition
    } else {
        match length {
            Some(n) if n > MAX_BODY => return Err(ApiError::Bad("response too large".into())),
            Some(n) => {
                body.resize(n, 0);
                r.read_exact(&mut body).map_err(|e| match io_err(&e) {
                    ApiError::Bad(_) => ApiError::Bad("truncated body".into()),
                    other => other,
                })?;
            }
            None => {
                (&mut r)
                    .take(MAX_BODY as u64 + 1)
                    .read_to_end(&mut body)
                    .map_err(|e| io_err(&e))?;
                if body.len() > MAX_BODY {
                    return Err(ApiError::Bad("response too large".into()));
                }
            }
        }
    }
    Ok(Response {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Reads with the socket timeout set to the time left until `deadline`.
struct Deadline<'a> {
    s: &'a UnixStream,
    deadline: Instant,
}

impl Deadline<'_> {
    fn left(&self) -> std::io::Result<Duration> {
        let d = self.deadline.saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(d)
        }
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.s.set_read_timeout(Some(self.left()?))?;
        (&*self.s).read(buf)
    }
}

/// Connect, giving up after `CONNECT_TIMEOUT`. `UnixStream::connect` blocks
/// when the listener backlog is full, so it runs on a helper thread that is
/// left to finish on its own after a timeout.
/// `api.sock` lives in a directory the VMM can write: only a socket is
/// connected to, never a symlink (which could lead to another box's VMM).
/// The check and the connect are not atomic; the VMM of this box could swap
/// the path in between, but only while it runs, and then it already holds
/// its own API.
fn connect(sock: &Path) -> Result<UnixStream, ApiError> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(sock) {
        Ok(m) if m.file_type().is_socket() => {}
        _ => return Err(ApiError::NoSocket),
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let p = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(p));
    });
    match rx.recv_timeout(CONNECT_TIMEOUT) {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                ApiError::NoSocket
            }
            _ => io_err(&e),
        }),
        Err(_) => Err(ApiError::Timeout),
    }
}

impl Api {
    pub fn new(sock: PathBuf) -> Api {
        Api { sock }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<Response, ApiError> {
        let deadline = Instant::now() + timeout;
        let mut s = connect(&self.sock)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ApiError::Timeout);
        }
        s.set_write_timeout(Some(left)).map_err(|e| io_err(&e))?;
        s.write_all(&request_bytes(method, path, body))
            .map_err(|e| io_err(&e))?;
        let resp = parse_response(Deadline { s: &s, deadline })?;
        if (200..300).contains(&resp.status) {
            Ok(resp)
        } else {
            Err(ApiError::Http {
                status: resp.status,
                body: resp.body,
            })
        }
    }

    /// `GET /api/v1/vmm.ping`, returning the VMM version.
    pub fn ping(&self) -> Result<String, ApiError> {
        let r = self.call("GET", "/api/v1/vmm.ping", None, QUERY_TIMEOUT)?;
        let v: serde_json::Value =
            serde_json::from_str(&r.body).map_err(|e| ApiError::Bad(e.to_string()))?;
        v.get("version")
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Bad("ping without version".into()))
    }

    /// `GET /api/v1/vm.info`, reading `state`.
    pub fn state(&self) -> Result<VmState, ApiError> {
        let r = self.call("GET", "/api/v1/vm.info", None, QUERY_TIMEOUT)?;
        let v: serde_json::Value =
            serde_json::from_str(&r.body).map_err(|e| ApiError::Bad(e.to_string()))?;
        match v.get("state").and_then(|x| x.as_str()) {
            Some("Created") => Ok(VmState::Created),
            Some("Running") => Ok(VmState::Running),
            Some("Paused") => Ok(VmState::Paused),
            Some("Shutdown") => Ok(VmState::Shutdown),
            other => Err(ApiError::Bad(format!("unknown vm state: {other:?}"))),
        }
    }

    /// `PUT` an action; 200 and 204 are success.
    pub fn put(
        &self,
        a: Action,
        body: Option<&serde_json::Value>,
        timeout: Duration,
    ) -> Result<(), ApiError> {
        let body = body.map(|b| b.to_string());
        self.call("PUT", a.path(), body.as_deref(), timeout)
            .map(|_| ())
    }

    pub fn snapshot(&self, dest: &Path) -> Result<(), ApiError> {
        let body = serde_json::json!({ "destination_url": format!("file://{}", dest.display()) });
        self.put(Action::Snapshot, Some(&body), SNAPSHOT_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ch-v54.0")
            .join(name);
        let raw = std::fs::read(&p).unwrap();
        let mut rest = &raw[..];
        while rest.first() == Some(&b'#') {
            let nl = rest.iter().position(|b| *b == b'\n').unwrap();
            rest = &rest[nl + 1..];
        }
        rest.to_vec()
    }

    #[test]
    fn request_bytes_are_exact() {
        let a = request_bytes("PUT", Action::Pause.path(), None);
        assert_eq!(
            String::from_utf8(a).unwrap(),
            "PUT /api/v1/vm.pause HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
        );
        let body = r#"{"destination_url":"file:///b/s"}"#;
        let b = request_bytes("PUT", Action::Snapshot.path(), Some(body));
        assert_eq!(
            String::from_utf8(b).unwrap(),
            format!("PUT /api/v1/vm.snapshot HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        );
        assert_eq!(Action::ShutdownVmm.path(), "/api/v1/vmm.shutdown");
        assert_eq!(Action::PowerButton.path(), "/api/v1/vm.power-button");
        assert_eq!(Action::Resume.path(), "/api/v1/vm.resume");
    }

    #[test]
    fn parses_each_fixture() {
        for (f, status) in [
            ("vmm.ping.200.http", 200),
            ("vm.info.running.200.http", 200),
            ("vm.info.paused.200.http", 200),
            ("vm.info.created.200.http", 200),
            ("vm.info.shutdown.200.http", 200),
            ("vm.pause.204.http", 204),
            ("vm.pause.500.http", 500),
            ("vm.snapshot.204.http", 204),
        ] {
            let r = parse_response(&fixture(f)[..]).unwrap();
            assert_eq!(r.status, status, "{f}");
        }
        let r = parse_response(&fixture("vm.pause.500.http")[..]).unwrap();
        assert_eq!(r.body, "InvalidStateTransition");
        let r = parse_response(&fixture("vm.info.paused.200.http")[..]).unwrap();
        assert!(r.body.contains("\"state\":\"Paused\""));
    }

    #[test]
    fn content_length_and_eof_bodies() {
        let a = parse_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"[..]).unwrap();
        assert_eq!(a.body, "abc");
        let b = parse_response(&b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nto eof"[..]).unwrap();
        assert_eq!(b.body, "to eof");
    }

    #[test]
    fn oversized_response_is_bad() {
        let mut v = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        v.extend(std::iter::repeat_n(b'x', MAX_BODY + 10));
        assert_eq!(
            parse_response(&v[..]),
            Err(ApiError::Bad("response too large".into()))
        );
        let h = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(
            parse_response(h.as_bytes()),
            Err(ApiError::Bad("response too large".into()))
        );
    }

    #[test]
    fn missing_socket_is_no_socket() {
        let api = Api::new(PathBuf::from("/nonexistent/p35/api.sock"));
        assert_eq!(api.ping(), Err(ApiError::NoSocket));
        assert_eq!(api.state(), Err(ApiError::NoSocket));
    }

    use std::os::unix::net::UnixListener;

    fn tmp_sock(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let d = tempfile::Builder::new()
            .prefix("u")
            .tempdir_in(base)
            .unwrap()
            .keep();
        let s = d.join(tag);
        (d, s)
    }

    /// Accept one connection on a thread and hand it to `f`.
    fn serve_once<F: FnOnce(UnixStream) + Send + 'static>(f: F) -> (PathBuf, PathBuf) {
        let (d, s) = tmp_sock("s");
        let l = UnixListener::bind(&s).unwrap();
        std::thread::spawn(move || {
            if let Ok((c, _)) = l.accept() {
                f(c);
            }
        });
        (d, s)
    }

    fn drain_request(c: &mut UnixStream) {
        let mut b = [0u8; 4096];
        let _ = c.read(&mut b);
    }

    #[test]
    fn huge_header_line_is_bounded() {
        let written = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = written.clone();
        let (d, s) = serve_once(move |mut c| {
            drain_request(&mut c);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nX: ");
            let chunk = [b'a'; 1024];
            for _ in 0..1024 {
                if c.write_all(&chunk).is_err() {
                    break;
                }
                w.fetch_add(1024, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let r = Api::new(s).state();
        assert_eq!(r, Err(ApiError::Bad("response headers too large".into())));
        std::thread::sleep(Duration::from_millis(200));
        // socket buffers hold some, but the client stopped reading at 8 KiB
        assert!(written.load(std::sync::atomic::Ordering::SeqCst) < 1024 * 1024);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn too_many_header_lines_is_bad() {
        let mut v = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..65 {
            v.extend_from_slice(b"X: y\r\n");
        }
        v.extend_from_slice(b"\r\n");
        assert_eq!(
            parse_response(&v[..]),
            Err(ApiError::Bad("response headers too large".into()))
        );
    }

    #[test]
    fn slow_drip_hits_the_deadline() {
        let (d, s) = serve_once(|mut c| {
            drain_request(&mut c);
            loop {
                if c.write_all(b"H").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let t = Instant::now();
        let r = Api::new(s).put(Action::Pause, None, Duration::from_secs(2));
        assert_eq!(r, Err(ApiError::Timeout));
        assert!(
            t.elapsed() < Duration::from_millis(2600),
            "{:?}",
            t.elapsed()
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn oversized_content_length_is_refused() {
        let r = parse_response(&b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nabc"[..]);
        assert_eq!(r, Err(ApiError::Bad("response too large".into())));
    }

    #[test]
    fn eof_body_past_cap_is_refused() {
        let mut v = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        v.extend(std::iter::repeat_n(b'x', MAX_BODY + 1));
        assert_eq!(
            parse_response(&v[..]),
            Err(ApiError::Bad("response too large".into()))
        );
        let mut ok = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        ok.extend(std::iter::repeat_n(b'x', MAX_BODY));
        assert_eq!(parse_response(&ok[..]).unwrap().body.len(), MAX_BODY);
    }

    #[test]
    fn chunked_and_conflicting_length_are_refused() {
        assert!(matches!(
            parse_response(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..]),
            Err(ApiError::Bad(_))
        ));
        assert!(matches!(
            parse_response(
                &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"[..]
            ),
            Err(ApiError::Bad(_))
        ));
    }

    #[test]
    fn bodyless_204_does_not_wait_for_eof() {
        let (d, s) = serve_once(|mut c| {
            drain_request(&mut c);
            let _ = c.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
            std::thread::sleep(Duration::from_secs(4));
        });
        let t = Instant::now();
        Api::new(s)
            .put(Action::Pause, None, Duration::from_secs(2))
            .unwrap();
        assert!(t.elapsed() < Duration::from_secs(1));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn symlinked_socket_is_not_followed() {
        let (d, s) = tmp_sock("real");
        let _l = UnixListener::bind(&s).unwrap();
        let link = s.with_file_name("link");
        std::os::unix::fs::symlink(&s, &link).unwrap();
        assert_eq!(Api::new(link.clone()).ping(), Err(ApiError::NoSocket));
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, b"x").unwrap();
        assert_eq!(Api::new(link).ping(), Err(ApiError::NoSocket));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn connect_refused_is_no_socket() {
        let (d, s) = tmp_sock("stale");
        drop(UnixListener::bind(&s).unwrap()); // leaves the socket file, no listener
        assert!(s.exists());
        assert_eq!(Api::new(s).ping(), Err(ApiError::NoSocket));
        let _ = std::fs::remove_dir_all(d);
    }
}
