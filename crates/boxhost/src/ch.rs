//! Cloud Hypervisor REST API client over its Unix socket (std only).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 64;
const MAX_HEADER_BYTES: usize = 8 * 1024;
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

pub(crate) fn parse_response<R: Read>(r: R) -> Result<Response, ApiError> {
    let mut r = BufReader::new(r);
    let mut line = String::new();
    let mut header_bytes = 0usize;
    let mut lines = 0usize;
    let mut status = None;
    let mut length: Option<usize> = None;
    loop {
        line.clear();
        let n = r.read_line(&mut line).map_err(|e| io_err(&e))?;
        if n == 0 {
            return Err(ApiError::Bad("truncated headers".into()));
        }
        header_bytes += n;
        lines += 1;
        if lines > MAX_HEADER_LINES || header_bytes > MAX_HEADER_BYTES {
            return Err(ApiError::Bad("headers too large".into()));
        }
        let t = line.trim_end_matches(['\r', '\n']);
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
            if k.eq_ignore_ascii_case("content-length") {
                length = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| ApiError::Bad("bad content-length".into()))?,
                );
            }
        }
    }
    let mut body = Vec::new();
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
            r.take(MAX_BODY as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| io_err(&e))?;
            if body.len() > MAX_BODY {
                return Err(ApiError::Bad("response too large".into()));
            }
        }
    }
    Ok(Response {
        status: status.unwrap_or(0),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
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
        let mut s = UnixStream::connect(&self.sock).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                ApiError::NoSocket
            }
            _ => io_err(&e),
        })?;
        s.set_read_timeout(Some(timeout)).map_err(|e| io_err(&e))?;
        s.set_write_timeout(Some(timeout)).map_err(|e| io_err(&e))?;
        s.write_all(&request_bytes(method, path, body))
            .map_err(|e| io_err(&e))?;
        let resp = parse_response(&mut s)?;
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
}
