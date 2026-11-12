//! `saiife-fake-ch`: a stand-in for cloud-hypervisor in tests. Accepts the
//! flags `launch::argv` produces, serves canned v54.0 responses on the API
//! socket and keeps a Running/Paused state machine.
//! Env knobs: FAKE_CH_IGNORE_POWER=1, FAKE_CH_HANG=1, FAKE_CH_EXIT_AT_START=<code>.

#[cfg(unix)]
mod imp {
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

    /// What the argv says, for the API socket and the snapshot's VmConfig.
    #[derive(Default)]
    struct Parsed {
        sock: Option<PathBuf>,
        restore: Option<PathBuf>,
        vals: Vec<(String, Vec<String>)>,
        landlock: bool,
    }

    impl Parsed {
        fn one(&self, flag: &str) -> Option<&str> {
            self.vals
                .iter()
                .find(|(f, _)| f == flag)
                .and_then(|(_, v)| v.first())
                .map(String::as_str)
        }
        fn many(&self, flag: &str) -> Vec<String> {
            self.vals
                .iter()
                .filter(|(f, _)| f == flag)
                .flat_map(|(_, v)| v.clone())
                .collect()
        }
    }

    /// `k=v,k=v` option lists.
    fn opt<'a>(v: &'a str, key: &str) -> Option<&'a str> {
        v.split(',')
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
    }

    /// A CH v54-shaped `VmConfig` built from the launch argv.
    fn vm_config(p: &Parsed) -> serde_json::Value {
        use serde_json::{json, Value};
        let disks: Vec<Value> = p
        .many("--disk")
        .iter()
        .enumerate()
        .map(|(i, d)| {
            json!({
                "path": opt(d, "path"), "readonly": false, "direct": false, "iommu": false,
                "num_queues": 1, "queue_size": 128, "vhost_user": false, "vhost_socket": null,
                "rate_limit_group": null, "rate_limiter_config": null, "id": format!("_disk{i}"),
                "disable_io_uring": false, "disable_aio": false, "pci_segment": 0,
                "serial": null, "queue_affinity": null,
                "backing_files": opt(d, "backing_files") == Some("on"),
                "image_type": if opt(d, "image_type") == Some("qcow2") { "Qcow2" } else { "Raw" }
            })
        })
        .collect();
        let boot: u64 = p
            .one("--cpus")
            .and_then(|c| opt(c, "boot")?.parse().ok())
            .unwrap_or(1);
        let mem: u64 = p
            .one("--memory")
            .and_then(|m| opt(m, "size")?.strip_suffix('M')?.parse().ok())
            .unwrap_or(512);
        let rules: Vec<Value> = p
            .many("--landlock-rules")
            .iter()
            .map(|r| json!({"path": opt(r, "path"), "access": opt(r, "access")}))
            .collect();
        json!({
            "cpus": {"boot_vcpus": boot, "max_vcpus": boot, "topology": null, "kvm_hyperv": false,
                     "max_phys_bits": 46, "affinity": null, "features": {}},
            "memory": {"size": mem << 20, "mergeable": false, "hotplug_method": "Acpi",
                       "hotplug_size": null, "hotplugged_size": null, "shared": false,
                       "hugepages": false, "hugepage_size": null, "prefault": false,
                       "zones": null, "thp": true},
            "payload": {"firmware": p.one("--firmware"), "kernel": p.one("--kernel"),
                        "cmdline": p.one("--cmdline"), "initramfs": null},
            "rate_limit_groups": null,
            "disks": disks,
            "net": null,
            "rng": {"src": "/dev/urandom", "iommu": false},
            "balloon": {"size": 0, "deflate_on_oom": true, "free_page_reporting": true},
            "fs": null,
            "pmem": null,
            "serial": {"file": p.one("--serial").and_then(|s| s.strip_prefix("file=")),
                       "mode": "File", "iommu": false, "socket": null},
            "console": {"file": null, "mode": "Off", "iommu": false, "socket": null},
            "debug_console": {"file": null, "mode": "Off", "iobase": 233},
            "devices": null,
            "user_devices": null,
            "vdpa": null,
            "vsock": {"cid": 3, "socket": p.one("--vsock").and_then(|v| opt(v, "socket")),
                      "iommu": false, "id": "_vsock0", "pci_segment": 0},
            "pvpanic": false,
            "iommu": false,
            "sgx_epc": null,
            "numa": null,
            "watchdog": false,
            "platform": null,
            "tpm": null,
            "preserved_fds": null,
            "landlock_enable": p.landlock,
            "landlock_rules": if rules.is_empty() { Value::Null } else { Value::Array(rules) }
        })
    }

    /// Flags and whether they take exactly one value (false: one or more).
    /// `--landlock` takes none.
    fn parse(args: &[String]) -> Result<Parsed, String> {
        let mut p = Parsed::default();
        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            i += 1;
            match flag {
                "--landlock" => p.landlock = true,
                "--firmware" | "--kernel" | "--cmdline" | "--cpus" | "--memory" | "--vsock"
                | "--balloon" | "--serial" | "--console" | "--api-socket" | "--restore" => {
                    let v = args.get(i).ok_or_else(|| format!("{flag} needs a value"))?;
                    i += 1;
                    match flag {
                        "--api-socket" => {
                            p.sock = Some(PathBuf::from(
                                v.strip_prefix("path=").ok_or("api-socket needs path=")?,
                            ));
                        }
                        "--restore" => {
                            let src = v
                                .strip_prefix("source_url=file://")
                                .ok_or("restore needs source_url=file://")?;
                            p.restore = Some(PathBuf::from(src));
                        }
                        _ => {}
                    }
                    p.vals.push((flag.to_string(), vec![v.clone()]));
                }
                "--disk" | "--landlock-rules" => {
                    let start = i;
                    while i < args.len() && !args[i].starts_with("--") {
                        i += 1;
                    }
                    if i == start {
                        return Err(format!("{flag} needs a value"));
                    }
                    p.vals.push((flag.to_string(), args[start..i].to_vec()));
                }
                other => return Err(format!("unknown flag {other}")),
            }
        }
        if p.sock.is_none() {
            return Err("no --api-socket".into());
        }
        Ok(p)
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
        /// The VmConfig a snapshot writes (from the argv, or the restored one).
        config: String,
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

    /// The snapshot files; FAKE_CH_SNAP_EVIL plays a hostile VMM:
    /// `dirlink:<dir>` (the snapshot dir is a symlink to `<dir>`),
    /// `link:<file>` / `hardlink:<file>` (memory-ranges links to `<file>`),
    /// `fifo` (memory-ranges is a FIFO), `extra` (an unexpected file),
    /// `huge:<MiB>` (a sparse memory-ranges of that size).
    fn write_snapshot(d: &std::path::Path, config: &str) -> bool {
        let evil = std::env::var("FAKE_CH_SNAP_EVIL").unwrap_or_default();
        let dir = match evil.strip_prefix("dirlink:") {
            Some(target) => {
                let t = PathBuf::from(target);
                // the launcher made the dir: a hostile VMM replaces it
                let _ = std::fs::remove_dir(d);
                if std::os::unix::fs::symlink(&t, d).is_err() {
                    return false;
                }
                t
            }
            None => {
                if std::fs::create_dir_all(d).is_err() {
                    return false;
                }
                d.to_path_buf()
            }
        };
        let _ = std::fs::write(dir.join("config.json"), config.as_bytes());
        let _ = std::fs::write(dir.join("state.json"), b"{\"fake_state\":true}\n");
        let mem = dir.join("memory-ranges");
        if let Some(t) = evil.strip_prefix("link:") {
            let _ = std::os::unix::fs::symlink(t, &mem);
        } else if let Some(t) = evil.strip_prefix("hardlink:") {
            let _ = std::fs::hard_link(t, &mem);
        } else if let Some(mib) = evil.strip_prefix("huge:") {
            // sparse: no disk is used until someone copies it
            let n: u64 = mib.parse().unwrap_or(0);
            let _ = std::fs::File::create(&mem).and_then(|f| f.set_len(n << 20));
        } else if evil == "fifo" {
            let _ = rustix::fs::mknodat(
                rustix::fs::CWD,
                &mem,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600),
                0,
            );
        } else {
            let _ = std::fs::write(&mem, b"guest memory");
        }
        if evil == "extra" {
            let _ = std::fs::write(dir.join("extra"), b"x");
        }
        true
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
                if !paused {
                    let _ = s.write_all(fx!("vm.pause.500.http").as_bytes());
                    return;
                }
                let dest = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| {
                        v.get("destination_url")?
                            .as_str()?
                            .strip_prefix("file://")
                            .map(PathBuf::from)
                    });
                match dest {
                    Some(d) if write_snapshot(&d, &sh.config) => fx!("vm.snapshot.204.http"),
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

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let parsed = match parse(&args) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("saiife-fake-ch: {e}");
                std::process::exit(2);
            }
        };
        let sock = parsed.sock.clone().unwrap_or_default();
        let restore = parsed.restore.is_some();
        // A restored VM keeps the snapshotted config (as CH does).
        let config = match &parsed.restore {
            Some(src) => std::fs::read_to_string(src.join("config.json")).unwrap_or_default(),
            None => vm_config(&parsed).to_string(),
        };
        if let Some(dir) = sock.parent() {
            let lines: String = args.iter().map(|a| json_str(a) + "\n").collect();
            let _ = std::fs::write(dir.join("fake-ch.argv"), lines);
        }
        if let Some(code) = std::env::var("FAKE_CH_EXIT_AT_START")
            .ok()
            .and_then(|c| c.parse::<i32>().ok())
        {
            std::process::exit(code);
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
            config,
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
}

#[cfg(unix)]
fn main() {
    imp::main();
}

#[cfg(not(unix))]
fn main() {}
