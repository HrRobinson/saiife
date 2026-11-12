//! `saiife-fake-ch`: a stand-in for cloud-hypervisor in tests. Accepts the
//! flags `launch::argv` produces, serves canned v54.0 responses on the API
//! socket and keeps a Running/Paused state machine.
//! Env knobs: FAKE_CH_IGNORE_POWER=1, FAKE_CH_HANG=1, FAKE_CH_EXIT_AT_START=<code>.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn fixture(raw: &str) -> &str {
    let mut rest = raw;
    while rest.starts_with('#') {
        rest = rest.split_once('\n').map_or("", |x| x.1);
    }
    rest
}

macro_rules! fx {
    ($n:literal) => {
        fixture(include_str!(concat!("../../tests/fixtures/ch-v54.0/", $n)))
    };
}

/// Flags and whether they take exactly one value (false: one or more).
/// `--landlock` takes none.
fn parse(args: &[String]) -> Result<(PathBuf, bool), String> {
    let mut sock = None;
    let mut restore = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        match flag {
            "--landlock" => {}
            "--firmware" | "--kernel" | "--cmdline" | "--cpus" | "--memory" | "--vsock"
            | "--balloon" | "--serial" | "--console" | "--api-socket" | "--restore" => {
                let v = args.get(i).ok_or_else(|| format!("{flag} needs a value"))?;
                i += 1;
                match flag {
                    "--api-socket" => {
                        sock = Some(PathBuf::from(
                            v.strip_prefix("path=").ok_or("api-socket needs path=")?,
                        ));
                    }
                    "--restore" => {
                        if !v.starts_with("source_url=file://") {
                            return Err("restore needs source_url=file://".into());
                        }
                        restore = true;
                    }
                    _ => {}
                }
            }
            "--disk" | "--landlock-rules" => {
                let start = i;
                while i < args.len() && !args[i].starts_with("--") {
                    i += 1;
                }
                if i == start {
                    return Err(format!("{flag} needs a value"));
                }
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok((sock.ok_or("no --api-socket")?, restore))
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

struct Shared {
    paused: Mutex<bool>,
    ignore_power: bool,
}

fn read_request(s: &mut UnixStream) -> Option<(String, String, String)> {
    let mut r = BufReader::new(s.try_clone().ok()?);
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    let mut it = line.split_whitespace();
    let method = it.next()?.to_string();
    let path = it.next()?.to_string();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().ok()?;
            }
        }
    }
    let mut body = vec![0u8; len.min(1 << 20)];
    r.read_exact(&mut body).ok()?;
    Some((method, path, String::from_utf8_lossy(&body).into_owned()))
}

fn exit_after(ms: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        std::process::exit(0);
    });
}

fn serve(mut s: UnixStream, sh: Arc<Shared>) {
    let Some((method, path, body)) = read_request(&mut s) else {
        return;
    };
    let paused = *sh.paused.lock().unwrap();
    let mut then_exit = false;
    let resp: &str = match (method.as_str(), path.as_str()) {
        ("GET", "/api/v1/vmm.ping") => fx!("vmm.ping.200.http"),
        ("GET", "/api/v1/vm.info") => {
            if paused {
                fx!("vm.info.paused.200.http")
            } else {
                fx!("vm.info.running.200.http")
            }
        }
        ("PUT", "/api/v1/vm.pause") | ("PUT", "/api/v1/vm.resume") => {
            let pause = path.ends_with("pause");
            let mut g = sh.paused.lock().unwrap();
            if *g == pause {
                fx!("vm.pause.500.http")
            } else {
                *g = pause;
                fx!("vm.pause.204.http")
            }
        }
        ("PUT", "/api/v1/vm.power-button") => {
            if !sh.ignore_power {
                exit_after(200);
            }
            fx!("vm.pause.204.http")
        }
        ("PUT", "/api/v1/vm.snapshot") => {
            let dest = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("destination_url")?
                        .as_str()?
                        .strip_prefix("file://")
                        .map(PathBuf::from)
                });
            match dest {
                Some(d) if std::fs::create_dir_all(&d).is_ok() => {
                    let _ = std::fs::write(d.join("config.json"), b"{\"fake\":true}\n");
                    fx!("vm.snapshot.204.http")
                }
                _ => fx!("vm.pause.500.http"),
            }
        }
        ("PUT", "/api/v1/vmm.shutdown") => {
            then_exit = true;
            fx!("vm.pause.204.http")
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    };
    let _ = s.write_all(resp.as_bytes());
    let _ = s.flush();
    if then_exit {
        std::process::exit(0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (sock, restore) = match parse(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("saiife-fake-ch: {e}");
            std::process::exit(2);
        }
    };
    if let Some(code) = std::env::var("FAKE_CH_EXIT_AT_START")
        .ok()
        .and_then(|c| c.parse::<i32>().ok())
    {
        std::process::exit(code);
    }
    if let Some(dir) = sock.parent() {
        let lines: String = args.iter().map(|a| json_str(a) + "\n").collect();
        let _ = std::fs::write(dir.join("fake-ch.argv"), lines);
    }
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("saiife-fake-ch: bind {}: {e}", sock.display());
            std::process::exit(1);
        }
    };
    let hang = std::env::var("FAKE_CH_HANG").is_ok_and(|v| v == "1");
    let sh = Arc::new(Shared {
        paused: Mutex::new(restore),
        ignore_power: std::env::var("FAKE_CH_IGNORE_POWER").is_ok_and(|v| v == "1"),
    });
    let held: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
    for conn in listener.incoming().flatten() {
        if hang {
            held.lock().unwrap().push(conn);
            continue;
        }
        let sh = Arc::clone(&sh);
        std::thread::spawn(move || serve(conn, sh));
    }
}
