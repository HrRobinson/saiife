//! `saiife dev`: the real binary against a fake `docker` (plan 24).
//!
//! The fake is a shell script in the test's tempdir, named by
//! `SAIIFE_DOCKER`. It logs each argv (`$*`, one line per call) and answers
//! by glob rules, first match wins, unmatched calls exit 0 with no output.
//! Nothing here runs the real Docker.
#![allow(dead_code)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::tmp::short_tempdir;
use common::{code, set_profile, stderr, stdout};
use tempfile::TempDir;

/// One reply of the fake: calls whose `$*` matches `glob` (a POSIX `case`
/// pattern; only `*` and `?` are special) get `stdout`, `stderr` and `code`.
pub struct Rule {
    pub glob: &'static str,
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

impl Rule {
    pub fn ok(glob: &'static str, stdout: impl Into<String>) -> Rule {
        Rule {
            glob,
            stdout: stdout.into(),
            stderr: String::new(),
            code: 0,
        }
    }

    pub fn fail(glob: &'static str, code: i32, stderr: impl Into<String>) -> Rule {
        Rule {
            glob,
            stdout: String::new(),
            stderr: stderr.into(),
            code,
        }
    }
}

/// `docker compose config --format json` for a repo with `web` (port 80,
/// published 8080) and `worker` (no ports, no expose), project `shop`.
pub const MODEL: &str = r#"{
  "name": "shop",
  "services": {
    "web": {
      "image": "nginx:1",
      "networks": { "default": null },
      "ports": [
        { "mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp" }
      ]
    },
    "worker": {
      "image": "busybox:1",
      "networks": { "default": null }
    }
  },
  "networks": { "default": { "name": "shop_default" } }
}"#;

/// The rows of plan 24's argv table marked *rule*, in its order. Every other
/// call falls through to the fake's default (exit 0, no output).
pub fn base_rules() -> Vec<Rule> {
    vec![
        Rule::ok("*config --format json*", MODEL),
        Rule::ok(
            "network inspect saiife-dev*",
            r#"{"saiife.managed":"true","saiife.dev.role":"network"}"#,
        ),
        Rule::fail(
            "container inspect saiife-dev-proxy*",
            1,
            "Error: No such container: saiife-dev-proxy",
        ),
        Rule::ok("run -d --name saiife-dev-proxy *", "0123456789ab"),
    ]
}

/// `glob` as a `case` pattern: `*` and `?` stay special, every other
/// non-alphanumeric character is escaped, so spaces, `{{`, `=` and `.` match
/// themselves.
fn case_pattern(glob: &str) -> String {
    let mut out = String::new();
    for c in glob.chars() {
        if c == '*' || c == '?' || c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.push('\\');
            out.push(c);
        }
    }
    out
}

/// A shell single-quoted word.
fn sq(p: &Path) -> String {
    format!("'{}'", p.to_str().unwrap().replace('\'', r"'\''"))
}

pub struct Dev {
    pub root: TempDir,
    pub repo_parent: PathBuf,
    pub state: PathBuf,
    pub config: PathBuf,
    pub log: PathBuf,
    pub docker: PathBuf,
}

impl Dev {
    /// A fresh sandbox whose fake answers the test's `rules` first, then
    /// `base_rules()`.
    pub fn with(rules: Vec<Rule>) -> Dev {
        let mut all = rules;
        all.extend(base_rules());
        Dev::new(&all)
    }

    /// A fresh sandbox whose fake answers exactly `rules`, in order.
    pub fn new(rules: &[Rule]) -> Dev {
        let root = short_tempdir();
        let r = root.path().to_path_buf();
        for d in ["home", "state", "config", "bin", "fake", "repos"] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        let fake = r.join("fake");
        let log = fake.join("calls.log");
        let docker = fake.join("docker");
        let mut script = String::from("#!/bin/sh\nPATH=/usr/bin:/bin\n");
        script.push_str(&format!("printf '%s\\n' \"$*\" >> {}\n", sq(&log)));
        script.push_str("case \"$*\" in\n");
        for (i, rule) in rules.iter().enumerate() {
            let out = fake.join(format!("r{i}.out"));
            let err = fake.join(format!("r{i}.err"));
            fs::write(&out, &rule.stdout).unwrap();
            fs::write(&err, &rule.stderr).unwrap();
            script.push_str(&format!(
                "  {})\n    cat {}\n    cat {} >&2\n    exit {}\n    ;;\n",
                case_pattern(rule.glob),
                sq(&out),
                sq(&err),
                rule.code
            ));
        }
        script.push_str("  *)\n    exit 0\n    ;;\nesac\n");
        fs::write(&docker, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Dev {
            repo_parent: r.join("repos"),
            state: r.join("state"),
            config: r.join("config"),
            log,
            docker,
            root,
        }
    }

    pub fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    pub fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    /// The command `saiife` would run in `dir`, with the sandbox environment
    /// and nothing inherited. A test may change it before running it.
    pub fn command(&self, args: &[&str], dir: &Path) -> Command {
        let r = self.root.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
        cmd.args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", self.bin())
            .env("SAIIFE_DOCKER", &self.docker)
            .env("SAIIFE_DEV_SKIP_PORT_BIND", "1")
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_RUNTIME_DIR", self.home().join("no-runtime"))
            .env("SAIIFE_DATA_DIR", r.join("data"))
            .env("SAIIFE_AUDIT_DIR", r.join("audit"));
        set_profile(&mut cmd, &self.home());
        cmd
    }

    pub fn saiife(&self, args: &[&str], dir: &Path) -> Output {
        self.command(args, dir)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    pub fn saiife_with_stdin(&self, args: &[&str], dir: &Path, input: &str) -> Output {
        use std::io::Write;
        let mut child = self
            .command(args, dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A child that exits before reading closes the pipe: not an error here.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait_with_output().unwrap()
    }

    /// Every `docker` argv the fake saw, in order.
    pub fn calls(&self) -> Vec<String> {
        match fs::read_to_string(&self.log) {
            Ok(s) => s.lines().map(str::to_string).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// A repo folder `repo_parent/<n>/<name>` holding `files`, canonical. A
    /// fresh `<n>` per call, so two repos can share a folder name.
    pub fn repo(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let n = fs::read_dir(&self.repo_parent).unwrap().count();
        let dir = self.repo_parent.join(n.to_string()).join(name);
        fs::create_dir_all(&dir).unwrap();
        for (rel, body) in files {
            let p = dir.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
        fs::canonicalize(dir).unwrap()
    }
}

#[test]
fn dev_help_lists_the_five_commands() {
    let d = Dev::new(&[]);
    let o = d.saiife(&["dev", "--help"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let help = stdout(&o);
    for name in ["up", "ls", "down", "gc", "ca"] {
        assert!(
            help.lines()
                .any(|l| l.trim_start().starts_with(&format!("{name} "))),
            "`{name}` missing from:\n{help}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn ca_prints_the_path_and_the_linux_steps() {
    let d = Dev::new(&[]);
    let o = d.saiife(&["dev", "ca"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    let dev_state = d.state.join("saiife").join("dev");
    let head = format!("saiife dev CA certificate: {}/", dev_state.display());
    for want in [
        head.as_str(),
        "update-ca-certificates",
        "trust anchor --store",
        "certutil -d sql:$HOME/.pki/nssdb",
        "saiife never adds it to a trust store",
    ] {
        assert!(out.contains(want), "{want:?} missing from:\n{out}");
    }
    assert!(!out.contains("security add-trusted-cert"), "{out}");
    assert!(!out.contains("-addstore Root"), "{out}");
    let cert = out
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("saiife dev CA certificate: "))
        .unwrap();
    let cert = Path::new(cert);
    assert!(cert.starts_with(&d.state), "{}", cert.display());
    assert!(cert.is_file(), "{}", cert.display());
    let home: Vec<_> = fs::read_dir(d.home()).unwrap().collect();
    assert!(home.is_empty(), "written under HOME: {home:?}");
    assert!(d.calls().is_empty(), "ca ran docker: {:?}", d.calls());
}

#[cfg(unix)]
#[test]
fn ca_works_without_docker() {
    let d = Dev::new(&[]);
    let mut cmd = d.command(&["dev", "ca"], d.root.path());
    cmd.env_remove("SAIIFE_DOCKER").stdin(Stdio::null());
    let o = cmd.output().unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).starts_with("saiife dev CA certificate: "));
}

#[cfg(unix)]
#[test]
fn no_docker_is_a_plain_error() {
    let d = Dev::new(&[]);
    let mut cmd = d.command(&["dev", "ls"], d.root.path());
    cmd.env_remove("SAIIFE_DOCKER").stdin(Stdio::null());
    let o = cmd.output().unwrap();
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("saiife dev: "), "{err}");
    assert!(err.contains("docker"), "{err}");
    assert!(stdout(&o).is_empty(), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn the_fake_answers_by_rule_and_logs_each_call() {
    // The harness itself: first matching rule wins, the default is a
    // silent exit 0, and `{{...}}` reaches the log literally.
    let d = Dev::with(vec![Rule::fail("ps -a *", 3, "boom")]);
    let run = |args: &[&str]| Command::new(&d.docker).args(args).output().unwrap();
    let o = run(&["compose", "-f", "x", "config", "--format", "json"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), MODEL);
    let o = run(&["ps", "-a", "--format", "{{.Names}}"]);
    assert_eq!(code(&o), 3);
    assert_eq!(stderr(&o), "boom");
    let o = run(&["container", "inspect", "saiife-dev-proxy"]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("No such container"));
    let o = run(&["volume", "ls"]);
    assert_eq!(code(&o), 0);
    assert!(o.stdout.is_empty() && o.stderr.is_empty());
    assert_eq!(
        d.calls(),
        [
            "compose -f x config --format json",
            "ps -a --format {{.Names}}",
            "container inspect saiife-dev-proxy",
            "volume ls",
        ]
    );
    let a = d.repo("shop", &[("compose.yaml", "services: {}\n")]);
    let b = d.repo("shop", &[]);
    assert_ne!(a, b);
    assert!(a.join("compose.yaml").is_file());
}

// ---- plan 24 Task 3: `saiife dev ls` ----

/// Seeds a project's state as `up` leaves it: `project.json`, and
/// `urls.json` when `urls` is not empty.
#[cfg(unix)]
fn seed_project(d: &Dev, name: &str, dir: &Path, last_up: Option<&str>, urls: &[&str]) {
    let pdir = d
        .state
        .join("saiife")
        .join("dev")
        .join("projects")
        .join(name);
    fs::create_dir_all(&pdir).unwrap();
    let state = serde_json::json!({
        "name": name,
        "dir": dir,
        "created": "2026-11-01T00:00:00Z",
        "last_up": last_up,
    });
    fs::write(pdir.join("project.json"), state.to_string()).unwrap();
    if !urls.is_empty() {
        fs::write(pdir.join("urls.json"), serde_json::json!(urls).to_string()).unwrap();
    }
}

/// The `ps -a` rule: one tab line per `(id, name, project, state)`.
#[cfg(unix)]
fn ps_rule(rows: &[(&str, &str, &str, &str)]) -> Rule {
    let body: String = rows
        .iter()
        .map(|(i, n, p, s)| format!("{i}\t{n}\t{p}\t{s}\n"))
        .collect();
    Rule::ok("ps -a --filter label=saiife.managed=true*", body)
}

#[cfg(unix)]
fn ls_json(d: &Dev) -> serde_json::Value {
    let o = d.saiife(&["dev", "ls", "--json"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    serde_json::from_str(&stdout(&o)).unwrap()
}

#[cfg(unix)]
#[test]
fn ls_shows_running_partial_and_stopped() {
    let d = Dev::with(vec![ps_rule(&[
        ("a1", "saiife-shop-web-1", "shop", "running"),
        ("a2", "saiife-shop-db-1", "shop", "running"),
        ("b1", "saiife-blog-web-1", "blog", "running"),
        ("b2", "saiife-blog-db-1", "blog", "exited"),
        ("c1", "saiife-docs-web-1", "docs", "exited"),
    ])]);
    let shop = d.repo("shop", &[]);
    let blog = d.repo("blog", &[]);
    let docs = d.repo("docs", &[]);
    seed_project(
        &d,
        "shop",
        &shop,
        Some("2026-11-10T09:12:00Z"),
        &["https://web.shop.localhost"],
    );
    seed_project(&d, "blog", &blog, None, &["https://web.blog.localhost"]);
    seed_project(&d, "docs", &docs, None, &["https://web.docs.localhost"]);
    let v = ls_json(&d);
    let rows = v["projects"].as_array().unwrap();
    let names: Vec<_> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["blog", "docs", "shop"]);
    assert_eq!(rows[0]["state"], "partial");
    assert_eq!(rows[0]["containers"]["running"], 1);
    assert_eq!(rows[0]["containers"]["total"], 2);
    assert_eq!(rows[1]["state"], "stopped");
    assert_eq!(rows[1]["containers"]["running"], 0);
    assert_eq!(rows[1]["containers"]["total"], 1);
    assert_eq!(rows[2]["state"], "running");
    assert_eq!(rows[2]["containers"]["total"], 2);
    assert_eq!(rows[2]["last_up"], "2026-11-10T09:12:00Z");
    assert!(rows[0]["last_up"].is_null());
    assert_eq!(rows[2]["urls"][0], "https://web.shop.localhost");
    assert_eq!(rows[2]["dir"], shop.to_str().unwrap());
    assert_eq!(v["proxy"], "absent");
    // The text form: URL lines for running and partial rows only.
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.starts_with("PROJECT"), "{out}");
    assert!(out.contains("https://web.shop.localhost"), "{out}");
    assert!(out.contains("https://web.blog.localhost"), "{out}");
    assert!(!out.contains("web.docs.localhost"), "{out}");
    assert!(out.contains("2026-11-10T09:12:00Z"), "{out}");
    assert!(out.ends_with("proxy: absent\n"), "{out}");
}

#[cfg(unix)]
#[test]
fn ls_shows_missing_when_the_folder_is_gone() {
    let d = Dev::with(vec![]);
    let gone = d.repo_parent.join("nowhere").join("old");
    seed_project(&d, "old", &gone, None, &["https://web.old.localhost"]);
    let v = ls_json(&d);
    assert_eq!(v["projects"][0]["state"], "missing");
    assert_eq!(v["projects"][0]["dir"], gone.to_str().unwrap());
    let o = d.saiife(&["dev", "ls"], d.root.path());
    let out = stdout(&o);
    let line = out.lines().find(|l| l.starts_with("old")).unwrap();
    assert!(line.contains("missing"), "{out}");
    assert!(line.contains(" -  "), "{out}");
    assert!(!out.contains("web.old.localhost"), "{out}");
}

#[cfg(unix)]
#[test]
fn ls_shows_an_orphan_from_labels() {
    let d = Dev::with(vec![ps_rule(&[(
        "g1",
        "saiife-ghost-web-1",
        "ghost",
        "exited",
    )])]);
    let v = ls_json(&d);
    let rows = v["projects"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{v}");
    assert_eq!(rows[0]["name"], "ghost");
    assert!(rows[0]["dir"].is_null());
    // No folder and nothing running: the P3 table says missing.
    assert_eq!(rows[0]["state"], "missing");
    assert_eq!(rows[0]["containers"]["total"], 1);
    assert_eq!(rows[0]["urls"].as_array().unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn ls_proxy_line() {
    let d = Dev::with(vec![ps_rule(&[("p1", "saiife-dev-proxy", "", "running")])]);
    let v = ls_json(&d);
    assert_eq!(v["proxy"], "running");
    assert_eq!(v["projects"].as_array().unwrap().len(), 0, "{v}");
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert!(stdout(&o).ends_with("proxy: running\n"), "{}", stdout(&o));
    let d = Dev::with(vec![ps_rule(&[("p1", "saiife-dev-proxy", "", "exited")])]);
    assert_eq!(ls_json(&d)["proxy"], "stopped");
}

#[cfg(unix)]
#[test]
fn ls_docker_down_is_unknown_and_exit_1() {
    let d = Dev::with(vec![Rule::fail(
        "ps -a *",
        1,
        "Cannot connect to the Docker daemon",
    )]);
    let shop = d.repo("shop", &[]);
    seed_project(&d, "shop", &shop, None, &[]);
    let o = d.saiife(&["dev", "ls", "--json"], d.root.path());
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert!(
        err.starts_with("saiife dev: docker did not answer, so states are unknown: "),
        "{err}"
    );
    assert!(err.contains("Cannot connect to the Docker daemon"), "{err}");
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["projects"][0]["name"], "shop");
    assert_eq!(v["projects"][0]["state"], "unknown");
    assert_eq!(v["proxy"], "unknown");
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(stdout(&o).contains("unknown"), "{}", stdout(&o));
    assert!(stdout(&o).ends_with("proxy: unknown\n"), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn ls_empty_says_how_to_start() {
    let d = Dev::with(vec![]);
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).starts_with(
            "No saiife dev projects yet. Run saiife dev up in a folder with a compose file.\n"
        ),
        "{}",
        stdout(&o)
    );
    assert_eq!(ls_json(&d)["projects"].as_array().unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn ls_a_mismatched_state_name_is_one_clear_line() {
    let d = Dev::with(vec![]);
    let shop = d.repo("shop", &[]);
    seed_project(&d, "shop", &shop, None, &[]);
    let pdir = d.state.join("saiife/dev/projects/other");
    fs::create_dir_all(&pdir).unwrap();
    fs::copy(
        d.state.join("saiife/dev/projects/shop/project.json"),
        pdir.join("project.json"),
    )
    .unwrap();
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("saiife dev: "), "{err}");
    assert!(stdout(&o).is_empty());
}

#[cfg(unix)]
#[test]
fn ls_text_has_no_escape_from_a_folder_name() {
    let d = Dev::with(vec![]);
    let dir = d.repo("a\u{1b}[31mb", &[]);
    seed_project(&d, "shop", &dir, None, &[]);
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.contains("shop"), "{out}");
}

#[test]
fn dev_page_states_its_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let page = fs::read_to_string(root.join("docs/dev.md")).unwrap();
    let heads = [
        "## Quick start",
        "## Names",
        "## HTTPS and the local CA",
        "## Quirks",
        "## Commands",
        "## Cleanup and labels",
        "## Limits",
    ];
    for want in heads.into_iter().chain([
        "saiife.managed=true",
        "saiife.dev.project",
        "update-ca-certificates",
        "trust anchor --store",
        "add-trusted-cert -d -r trustRoot",
        "certutil -user -addstore Root",
        "Dangling images are not touched",
        "--yes",
        "COMPOSE_FILE",
        "not a security boundary",
    ]) {
        assert!(page.contains(want), "docs/dev.md lacks {want:?}");
    }
    let at = |h: &str| page.find(h).unwrap();
    assert!(
        heads.windows(2).all(|w| at(w[0]) < at(w[1])),
        "heading order"
    );
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    assert!(readme.contains("docs/dev.md"), "README lacks docs/dev.md");
}
