//! `saiife __mcp-spawn` (plan 17, Task 5): the spawn helper of the MCP
//! gateway, run against `saiife __fake-mcp-server`.
//!
//! Landlock is applied only inside the helper this test spawns. On a
//! kernel without Landlock the sandbox tests assert the fallback instead
//! (the helper refuses with `sandbox unavailable`, exit 126, and the
//! server never starts); `SAIIFE_REQUIRE_LANDLOCK=1` (the locked-linux CI
//! job) turns a missing Landlock into a failure.
#![cfg(target_os = "linux")]

use saiife_system::sandbox::{encode_spec, landlock_abi, Sandbox, SpawnSpec, CHILD_PATH};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use zeroize::Zeroizing;

const BIN: &str = env!("CARGO_BIN_EXE_saiife");

fn tempdir() -> TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("ms")
        .tempdir_in(base)
        .unwrap()
}

struct T {
    dir: TempDir,
    /// `$CREDENTIALS_DIRECTORY` for the helper, as systemd sets it.
    creds: Option<PathBuf>,
}

impl T {
    fn new() -> T {
        let t = T {
            dir: tempdir(),
            creds: None,
        };
        std::fs::create_dir(t.home()).unwrap();
        std::fs::set_permissions(t.home(), std::fs::Permissions::from_mode(0o700)).unwrap();
        t
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn spec(&self, sandbox: Sandbox) -> SpawnSpec {
        SpawnSpec {
            command: PathBuf::from(BIN),
            args: vec!["__fake-mcp-server".into(), "--read-file-tool".into()],
            env: vec![],
            home: self.home(),
            // The fake is the test binary: its dir must be readable.
            read_paths: vec![Path::new(BIN).parent().unwrap().to_path_buf()],
            sandbox,
            protected: vec![],
        }
    }
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    /// The result of the call with this id.
    fn result(&self, id: i64) -> Value {
        for line in self.stdout.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            if v["id"] == json!(id) {
                return v["result"].clone();
            }
        }
        panic!(
            "no answer to {id}: stdout {} stderr {}",
            self.stdout, self.stderr
        );
    }

    fn text(&self, id: i64) -> String {
        self.result(id)["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn introspect(&self, id: i64) -> Value {
        serde_json::from_str(&self.text(id)).unwrap()
    }
}

/// Runs the helper with `stdin` as its whole input. `sh_fds` opens these
/// extra descriptors (on /dev/null, without close-on-exec) through bash,
/// which, unlike dash, takes multi-digit descriptors.
fn run_raw(t: &T, stdin: &[u8], sh_fds: &[i32]) -> Out {
    let mut c = if sh_fds.is_empty() {
        let mut c = Command::new(BIN);
        c.arg("__mcp-spawn");
        c
    } else {
        let opens: Vec<String> = sh_fds.iter().map(|f| format!("{f}</dev/null")).collect();
        let mut c = Command::new("/bin/bash");
        c.arg("-c")
            .arg(format!("exec \"$0\" __mcp-spawn {}", opens.join(" ")))
            .arg(BIN);
        c
    };
    let fake_home = t.dir.path().join("caller-home");
    let _ = std::fs::create_dir(&fake_home);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fake_home)
        .env("SAIIFE_TEST_JUNK", "leak")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .current_dir(t.dir.path())
        .stdin(Stdio::piped())
        .envs(t.creds.iter().map(|c| ("CREDENTIALS_DIRECTORY", c)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let mut w = child.stdin.take().unwrap();
    // A refusing helper may exit before it reads everything.
    let _ = w.write_all(stdin);
    drop(w);
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("__mcp-spawn did not finish in 30 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    Out {
        code: status.code(),
        stdout,
        stderr,
    }
}

fn frame(spec: &SpawnSpec) -> Vec<u8> {
    encode_spec(spec).unwrap().to_vec()
}

/// The spec, then an MCP session: initialize, initialized, then one
/// `tools/call` per entry, with ids 2, 3, ...
fn session(spec: &SpawnSpec, calls: &[(&str, Value)]) -> Vec<u8> {
    let mut b = frame(spec);
    let mut line = |v: Value| {
        b.extend_from_slice(v.to_string().as_bytes());
        b.push(b'\n');
    };
    line(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    );
    line(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    for (i, (name, args)) in calls.iter().enumerate() {
        line(
            json!({"jsonrpc":"2.0","id":i as i64 + 2,"method":"tools/call",
            "params":{"name":name,"arguments":args}}),
        );
    }
    b
}

fn run(t: &T, spec: &SpawnSpec, calls: &[(&str, Value)]) -> Out {
    run_raw(t, &session(spec, calls), &[])
}

/// On a kernel without Landlock, a sandboxed spawn must be refused: exit
/// 126, `sandbox unavailable`, and the server never answers.
fn assert_fallback_refused(out: &Out) {
    assert_eq!(out.code, Some(126), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("sandbox unavailable"), "{}", out.stderr);
    assert!(out.stdout.is_empty(), "the server ran: {}", out.stdout);
    eprintln!("no Landlock on this kernel: asserted the fallback (sandbox_unavailable)");
}

#[test]
fn landlock_abi_reported() {
    let abi = landlock_abi();
    eprintln!("Landlock ABI {abi}");
    if std::env::var_os("SAIIFE_REQUIRE_LANDLOCK").is_some_and(|v| v == "1") {
        assert!(abi >= 1, "this runner must have Landlock (ABI >= 1)");
    }
}

#[test]
fn spawn_clears_env_keeps_secret_vars() {
    let t = T::new();
    let mut spec = t.spec(Sandbox::Off);
    let token = concat!("fake-", "mcp-", "token-value");
    spec.env = vec![("API_TOKEN".into(), Zeroizing::new(token.into()))];
    let out = run(&t, &spec, &[("introspect", json!({}))]);
    let env = out.introspect(2)["env"].as_object().unwrap().clone();
    let mut names: Vec<&str> = env.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["API_TOKEN", "HOME", "LANG", "PATH", "TMPDIR"]);
    assert_eq!(env["API_TOKEN"], token);
    assert_eq!(env["PATH"], CHILD_PATH);
    assert_eq!(env["LANG"], "C.UTF-8");
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

#[test]
fn spawn_sets_home_and_cwd() {
    let t = T::new();
    let out = run(&t, &t.spec(Sandbox::Off), &[("introspect", json!({}))]);
    let i = out.introspect(2);
    let home = t.home().display().to_string();
    assert_eq!(i["cwd"], home);
    assert_eq!(i["env"]["HOME"], home);
    // /tmp is not writable under the sandbox: temp files go to the home.
    assert_eq!(i["env"]["TMPDIR"], home);
}

#[test]
fn sandbox_denies_read_outside_allow_list() {
    let t = T::new();
    let vault = t.dir.path().join("vault.age");
    std::fs::write(&vault, "vault-contents").unwrap();
    let spec = t.spec(Sandbox::Landlock);
    let mut calls = vec![("read_file", json!({"path": vault}))];
    // Under /etc only the listed files are readable.
    if Path::new("/etc/hostname").exists() {
        calls.push(("read_file", json!({"path": "/etc/hostname"})));
    }
    let out = run(&t, &spec, &calls);
    if landlock_abi() == 0 {
        return assert_fallback_refused(&out);
    }
    for id in 2..2 + calls.len() as i64 {
        let r = out.result(id);
        assert_eq!(r["isError"], true, "{r}");
        assert_eq!(r["content"][0]["text"], "read_file: EACCES");
    }
    assert!(!out.stdout.contains("vault-contents"));
}

#[test]
fn sandbox_allows_read_paths() {
    let t = T::new();
    let allowed = t.dir.path().join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    std::fs::write(allowed.join("data.txt"), "listed").unwrap();
    std::fs::write(t.home().join("own.txt"), "own").unwrap();
    let mut spec = t.spec(Sandbox::Landlock);
    spec.read_paths.push(allowed.clone());
    let out = run(
        &t,
        &spec,
        &[
            ("read_file", json!({"path": allowed.join("data.txt")})),
            ("read_file", json!({"path": t.home().join("own.txt")})),
            ("read_file", json!({"path": "/etc/passwd"})),
            ("introspect", json!({})),
        ],
    );
    if landlock_abi() == 0 {
        return assert_fallback_refused(&out);
    }
    assert_eq!(out.text(2), "listed");
    assert_eq!(out.text(3), "own");
    assert_eq!(out.result(4)["isError"], false);
    // /proc/self is the server's own.
    assert_eq!(out.introspect(5)["no_new_privs"], "1");
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

#[test]
fn no_new_privs_set() {
    let t = T::new();
    let out = run(&t, &t.spec(Sandbox::Off), &[("introspect", json!({}))]);
    assert_eq!(out.introspect(2)["no_new_privs"], "1");
}

#[test]
fn fds_above_2_closed() {
    let t = T::new();
    // Without the sandbox, and with it (the closing shell runs confined).
    for sandbox in [Sandbox::Off, Sandbox::Landlock] {
        let out = run_raw(
            &t,
            &session(&t.spec(sandbox), &[("introspect", json!({}))]),
            &[5, 7],
        );
        if sandbox == Sandbox::Landlock && landlock_abi() == 0 {
            assert_fallback_refused(&out);
            continue;
        }
        assert_eq!(out.introspect(2)["fds"], json!([0, 1, 2]), "{sandbox:?}");
    }
    // A descriptor above 9 cannot be closed by a POSIX shell (dash reads
    // `12<&-` as the word 12): the helper refuses instead of leaking it.
    for fds in [&[12][..], &[5, 12]] {
        let out = run_raw(
            &t,
            &session(&t.spec(Sandbox::Off), &[("introspect", json!({}))]),
            fds,
        );
        assert_eq!(out.code, Some(126), "{fds:?}: {}", out.stderr);
        assert!(
            out.stderr.contains("an inherited descriptor above 9"),
            "{}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "the server ran: {}", out.stdout);
    }
}

#[test]
fn home_is_not_executable() {
    let t = T::new();
    // A program the server could have written into its own home.
    let prog = t.home().join("dropped");
    std::fs::write(&prog, "#!/bin/sh\necho ran-from-home\n").unwrap();
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut spec = t.spec(Sandbox::Landlock);
    spec.command = prog.clone();
    spec.args.clear();
    let out = run(&t, &spec, &[]);
    if landlock_abi() == 0 {
        return assert_fallback_refused(&out);
    }
    assert_eq!(out.code, Some(126), "{}", out.stderr);
    assert!(
        out.stderr.contains("cannot exec the server"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains("ran-from-home"));
    // Unconfined, the same program runs: the denial is the sandbox's.
    spec.sandbox = Sandbox::Off;
    let out = run(&t, &spec, &[]);
    assert!(out.stdout.contains("ran-from-home"), "{}", out.stderr);
}

#[test]
fn bad_spec_exits_126_without_values() {
    let t = T::new();
    let secret = concat!("sekrit-", "value-", "42");
    let rel = "relative/server-path";
    let body = |v: Value| {
        let b = v.to_string().into_bytes();
        let mut f = (b.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(&b);
        f
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty stdin", Vec::new()),
        ("short length", vec![0, 0]),
        ("over 64 KiB", (70_000u32).to_be_bytes().to_vec()),
        ("not json", {
            let mut f = 20u32.to_be_bytes().to_vec();
            f.extend_from_slice(format!("{{{secret}").as_bytes());
            f.resize(24, b' ');
            f
        }),
        (
            "relative command",
            body(
                json!({"command": rel, "args": [], "env": [["API_TOKEN", secret]],
                "home": t.home(), "read_paths": [], "sandbox": "off"}),
            ),
        ),
        (
            "unknown field",
            body(
                json!({"command": BIN, "args": [], "env": [["API_TOKEN", secret]],
                "home": t.home(), "read_paths": [], "sandbox": "off", "extra": secret}),
            ),
        ),
        (
            "reserved variable",
            body(
                json!({"command": BIN, "args": [], "env": [["LD_PRELOAD", secret]],
                "home": t.home(), "read_paths": [], "sandbox": "off"}),
            ),
        ),
        (
            "missing home",
            body(
                json!({"command": BIN, "args": [], "env": [["API_TOKEN", secret]],
                "home": t.dir.path().join("absent"), "read_paths": [], "sandbox": "off"}),
            ),
        ),
    ];
    for (what, input) in cases {
        let out = run_raw(&t, &input, &[]);
        assert_eq!(out.code, Some(126), "{what}: {}", out.stderr);
        assert_eq!(out.stderr.lines().count(), 1, "{what}: {}", out.stderr);
        assert!(
            out.stderr.starts_with("saiife: __mcp-spawn: "),
            "{what}: {}",
            out.stderr
        );
        assert!(!out.stderr.contains(secret), "{what}: {}", out.stderr);
        assert!(!out.stderr.contains(rel), "{what}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{what}");
    }
}

#[test]
fn sandbox_off_skips_landlock() {
    let t = T::new();
    let vault = t.dir.path().join("vault.age");
    std::fs::write(&vault, "vault-contents").unwrap();
    let out = run(
        &t,
        &t.spec(Sandbox::Off),
        &[("read_file", json!({"path": vault}))],
    );
    assert_eq!(out.text(2), "vault-contents");
}

#[test]
fn exec_outside_allow_list_refused() {
    let t = T::new();
    let mut spec = t.spec(Sandbox::Landlock);
    spec.read_paths.clear();
    let out = run(&t, &spec, &[]);
    if landlock_abi() == 0 {
        return assert_fallback_refused(&out);
    }
    assert_eq!(out.code, Some(126), "{}", out.stderr);
    assert!(
        out.stderr.contains("cannot exec the server"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains(BIN), "{}", out.stderr);
}

/// A refused spawn: exit 126, this reason, and the server never ran.
fn assert_read_path_refused(out: &Out, why: &str) {
    if landlock_abi() == 0 {
        return assert_fallback_refused(out);
    }
    assert_eq!(out.code, Some(126), "{}", out.stderr);
    assert!(
        out.stderr.contains(&format!("a read path {why}")),
        "{}",
        out.stderr
    );
    assert!(out.stdout.is_empty(), "the server ran: {}", out.stdout);
}

/// Policy load saw a harmless path; by spawn time it is a symlink to a
/// protected dir (here a temp stand-in for the daemon's state dir, passed
/// in the spec as the daemon passes its real layout). The helper resolves
/// the opened path and refuses.
#[test]
fn read_path_symlinked_to_protected_after_load_refused_at_spawn() {
    let t = T::new();
    let state = t.dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("vault.age"), "vault-contents").unwrap();
    let harmless = t.dir.path().join("docs");
    std::fs::create_dir(&harmless).unwrap();
    std::fs::write(harmless.join("a.txt"), "doc").unwrap();
    let link = t.dir.path().join("shared");
    std::os::unix::fs::symlink(&harmless, &link).unwrap();

    let mut spec = t.spec(Sandbox::Landlock);
    spec.read_paths.push(link.clone());
    spec.protected = vec![state.clone()];
    // As loaded: the link points somewhere harmless and is allowed.
    let out = run(
        &t,
        &spec,
        &[("read_file", json!({"path": link.join("a.txt")}))],
    );
    if landlock_abi() == 0 {
        return assert_fallback_refused(&out);
    }
    assert_eq!(out.text(2), "doc");

    // Re-pointed after load.
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&state, &link).unwrap();
    let out = run(
        &t,
        &spec,
        &[("read_file", json!({"path": link.join("vault.age")}))],
    );
    assert_read_path_refused(&out, "reaches saiife's own files");
    assert!(!out.stderr.contains("vault"), "{}", out.stderr);

    // A dir that holds a protected one is refused too.
    let mut spec2 = t.spec(Sandbox::Landlock);
    spec2.read_paths.push(t.dir.path().to_path_buf());
    spec2.protected = vec![state];
    assert_read_path_refused(&run(&t, &spec2, &[]), "reaches saiife's own files");
}

#[test]
fn read_path_in_credentials_directory_refused() {
    let mut t = T::new();
    let creds = t.dir.path().join("credentials");
    std::fs::create_dir(&creds).unwrap();
    std::fs::write(creds.join("vault-key"), "key").unwrap();
    t.creds = Some(creds.clone());
    let mut spec = t.spec(Sandbox::Landlock);
    spec.read_paths.push(creds);
    assert_read_path_refused(&run(&t, &spec, &[]), "reaches saiife's own files");
}

#[test]
fn read_path_that_cannot_be_opened_fails_closed() {
    let t = T::new();
    let mut spec = t.spec(Sandbox::Landlock);
    spec.read_paths.push(t.dir.path().join("absent"));
    assert_read_path_refused(&run(&t, &spec, &[]), "cannot be opened");
}
