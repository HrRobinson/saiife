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

// ---- plan 24 Task 4: `saiife dev down` ----

/// A seeded project with a `compose.json`, as `up` leaves it. Returns the repo.
#[cfg(unix)]
fn seed_up(d: &Dev, name: &str) -> PathBuf {
    let repo = d.repo(name, &[]);
    seed_project(
        d,
        name,
        &repo,
        None,
        &[&format!("https://web.{name}.localhost")],
    );
    let pdir = d.state.join("saiife/dev/projects").join(name);
    fs::write(pdir.join("compose.json"), "{}").unwrap();
    let dynamic = d.state.join("saiife/dev/proxy/dynamic");
    fs::create_dir_all(&dynamic).unwrap();
    fs::write(dynamic.join(format!("{name}.toml")), "").unwrap();
    repo
}

#[cfg(unix)]
#[test]
fn down_runs_compose_down_and_removes_routes() {
    let d = Dev::with(vec![]);
    let repo = seed_up(&d, "shop");
    let o = d.saiife(&["dev", "down", "shop"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("saiife dev: shop is down."),
        "{}",
        stdout(&o)
    );
    let compose = d.state.join("saiife/dev/projects/shop/compose.json");
    let want = format!(
        "compose -p saiife-shop --project-directory {} -f {} down",
        repo.display(),
        compose.display()
    );
    let calls = d.calls();
    assert!(calls.contains(&want), "{want}\n{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("--volumes")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("volume rm")), "{calls:?}");
    assert!(!d.state.join("saiife/dev/proxy/dynamic/shop.toml").exists());
    assert!(d
        .state
        .join("saiife/dev/projects/shop/project.json")
        .is_file());
}

#[cfg(unix)]
#[test]
fn down_rejects_a_bad_name() {
    for bad in ["../../etc", "Shop", "", "a/b"] {
        let d = Dev::with(vec![]);
        let o = d.saiife(&["dev", "down", bad], d.root.path());
        assert_eq!(code(&o), 1, "{bad:?}");
        assert!(
            stderr(&o).contains("is not a saiife dev project name"),
            "{bad:?}: {}",
            stderr(&o)
        );
        assert!(d.calls().is_empty(), "{bad:?}: {:?}", d.calls());
    }
}

#[cfg(unix)]
#[test]
fn down_unknown_project() {
    let d = Dev::with(vec![]);
    let o = d.saiife(&["dev", "down", "nope"], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains("no project named nope"),
        "{}",
        stderr(&o)
    );
}

#[cfg(unix)]
#[test]
fn down_refuses_foreign_containers() {
    let d = Dev::with(vec![Rule::ok(
        "ps -a --filter label=com.docker.compose.project=saiife-shop*",
        "saiife-shop-web-1\ttrue\nmine\t\n",
    )]);
    seed_up(&d, "shop");
    let o = d.saiife(
        &["dev", "down", "shop", "--volumes", "--yes"],
        d.root.path(),
    );
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert!(
        err.contains("containers saiife did not create (mine)"),
        "{err}"
    );
    assert!(err.contains("nothing was touched"), "{err}");
    let calls = d.calls();
    assert!(!calls.iter().any(|c| c.contains("down")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.starts_with("rm ")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("volume rm")), "{calls:?}");
}

#[cfg(unix)]
#[test]
fn down_volumes_without_yes_deletes_nothing() {
    let d = Dev::with(vec![Rule::ok("volume ls*", "saiife-shop_db\n")]);
    seed_up(&d, "shop");
    let o = d.saiife(&["dev", "down", "shop", "--volumes"], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains(
            "saiife dev: deleting volumes needs a yes. Run it in a terminal, or add --yes."
        ),
        "{}",
        stderr(&o)
    );
    let calls = d.calls();
    assert!(!calls.iter().any(|c| c.contains(" down")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("volume rm")), "{calls:?}");
    assert!(d.state.join("saiife/dev/proxy/dynamic/shop.toml").exists());
}

#[cfg(unix)]
#[test]
fn down_volumes_with_yes_removes_only_listed() {
    let d = Dev::with(vec![Rule::ok("volume ls*", "saiife-shop_db\n")]);
    seed_up(&d, "shop");
    let o = d.saiife(
        &["dev", "down", "shop", "--volumes", "--yes"],
        d.root.path(),
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("Volumes deleted: saiife-shop_db."),
        "{}",
        stdout(&o)
    );
    let calls = d.calls();
    let ls = calls
        .iter()
        .position(|c| c.starts_with("volume ls"))
        .unwrap();
    let rm = calls
        .iter()
        .position(|c| c.starts_with("volume rm"))
        .unwrap();
    assert!(ls < rm, "{calls:?}");
    assert!(calls[ls].contains("--filter label=saiife.managed=true"));
    assert!(calls[ls].contains("--filter label=saiife.dev.project=shop"));
    assert_eq!(calls[rm], "volume rm saiife-shop_db");
    assert_eq!(calls.iter().filter(|c| c.contains("volume rm")).count(), 1);
}

#[cfg(unix)]
#[test]
fn down_volumes_piped_answer_is_not_a_yes() {
    let d = Dev::with(vec![Rule::ok("volume ls*", "saiife-shop_db\n")]);
    seed_up(&d, "shop");
    let o = d.saiife_with_stdin(&["dev", "down", "shop", "--volumes"], d.root.path(), "y\n");
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains("deleting volumes needs a yes"),
        "{}",
        stderr(&o)
    );
    assert!(
        !d.calls().iter().any(|c| c.contains("volume rm")),
        "{:?}",
        d.calls()
    );
}

#[cfg(unix)]
#[test]
fn down_without_compose_json_removes_by_label() {
    let d = Dev::with(vec![
        Rule::ok("ps -aq*", "c1\nc2\n"),
        Rule::ok("network ls -q*", "n1\n"),
    ]);
    seed_up(&d, "shop");
    fs::remove_file(d.state.join("saiife/dev/projects/shop/compose.json")).unwrap();
    let o = d.saiife(&["dev", "down", "shop"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let calls = d.calls();
    let both = "--filter label=saiife.managed=true --filter label=saiife.dev.project=shop";
    let pos = |want: String| calls.iter().position(|c| *c == want).unwrap();
    let ps = pos(format!("ps -aq {both}"));
    let rm = pos("rm -f c1 c2".to_string());
    let nl = pos(format!("network ls -q {both}"));
    let nr = pos("network rm n1".to_string());
    assert!(ps < rm && rm < nl && nl < nr, "{calls:?}");
    assert!(
        !calls.iter().any(|c| c.starts_with("compose ")),
        "{calls:?}"
    );
}

// ---- plan 24 Task 2: `saiife dev up` ----

/// `<state>/saiife/dev/projects/<p>`.
#[cfg(unix)]
fn project_state_dir(d: &Dev, p: &str) -> PathBuf {
    d.state.join("saiife/dev/projects").join(p)
}

#[cfg(unix)]
fn shop_repo(d: &Dev) -> PathBuf {
    d.repo("shop", &[("compose.yaml", "services: {}\n")])
}

/// Every logged call ending `up -d`.
#[cfg(unix)]
fn up_calls(d: &Dev) -> Vec<String> {
    d.calls()
        .into_iter()
        .filter(|c| c.ends_with(" up -d"))
        .collect()
}

#[cfg(unix)]
fn has_key(v: &serde_json::Value, key: &str) -> bool {
    match v {
        serde_json::Value::Object(m) => m.iter().any(|(k, v)| k == key || has_key(v, key)),
        serde_json::Value::Array(a) => a.iter().any(|v| has_key(v, key)),
        _ => false,
    }
}

#[cfg(unix)]
fn read_json(p: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn up_routes_and_prints_urls() {
    let d = Dev::with(vec![]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.starts_with("saiife dev: shop is up (compose project saiife-shop).\n"),
        "{out}"
    );
    assert!(out.contains("\n  https://web.shop.localhost\n"), "{out}");
    let quirks = d.config.join("saiife/dev/shop.toml");
    let not_routed = format!(
        "Not routed (no port): worker. Set a port in {}.\n",
        quirks.display()
    );
    assert!(out.contains(&not_routed), "{out}");
    let pdir = project_state_dir(&d, "shop");
    let compose = pdir.join("compose.json");
    let want = format!(
        "compose -p saiife-shop --project-directory {} -f {} up -d",
        repo.display(),
        compose.display()
    );
    assert_eq!(up_calls(&d), [want]);
    let model = read_json(&compose);
    assert!(!has_key(&model, "ports"), "{model}");
    assert_eq!(model["name"], "saiife-shop");
    let state = read_json(&pdir.join("project.json"));
    let last_up = state["last_up"].as_str().unwrap();
    time::OffsetDateTime::parse(last_up, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|e| panic!("{last_up}: {e}"));
    assert_eq!(
        read_json(&pdir.join("urls.json")),
        serde_json::json!(["https://web.shop.localhost"])
    );
    assert!(d.state.join("saiife/dev/proxy/dynamic/shop.toml").is_file());
}

#[cfg(unix)]
#[test]
fn up_defaults_to_the_cwd() {
    let d = Dev::with(vec![]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up"], &repo);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("https://web.shop.localhost"),
        "{}",
        stdout(&o)
    );
    let calls = up_calls(&d);
    assert_eq!(calls.len(), 1, "{calls:?}");
    let dir_arg = format!("--project-directory {} ", repo.display());
    assert!(calls[0].starts_with("compose -p saiife-shop "), "{calls:?}");
    assert!(calls[0].contains(&dir_arg), "{calls:?}");
    let state = read_json(&project_state_dir(&d, "shop").join("project.json"));
    assert_eq!(state["dir"], repo.to_str().unwrap());
}

#[cfg(unix)]
#[test]
fn same_folder_name_gets_dash_two() {
    let d = Dev::with(vec![]);
    let a = shop_repo(&d);
    let b = shop_repo(&d);
    let up = |dir: &Path| {
        let o = d.saiife(&["dev", "up", dir.to_str().unwrap()], d.root.path());
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        stdout(&o)
    };
    assert!(up(&a).contains("https://web.shop.localhost\n"));
    let second = up(&b);
    assert!(
        second.contains("https://web.shop-2.localhost\n"),
        "{second}"
    );
    assert!(
        second.starts_with("saiife dev: shop-2 is up (compose project saiife-shop-2).\n"),
        "{second}"
    );
    let third = up(&a);
    assert!(third.contains("https://web.shop.localhost\n"), "{third}");
    assert!(!third.contains("shop-2"), "{third}");
}

#[cfg(unix)]
#[test]
fn compose_json_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let d = Dev::with(vec![]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let pdir = project_state_dir(&d, "shop");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&pdir.join("compose.json")), 0o600);
    assert_eq!(mode(&pdir.join("urls.json")), 0o600);
    assert_eq!(mode(&pdir), 0o700);
}

/// Every entry under `dir`, sorted: (path, len, mtime).
#[cfg(unix)]
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(p) = todo.pop() {
        let meta = fs::symlink_metadata(&p).unwrap();
        out.push((p.clone(), meta.len(), meta.modified().unwrap()));
        if meta.is_dir() {
            for e in fs::read_dir(&p).unwrap() {
                todo.push(e.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

#[cfg(unix)]
#[test]
fn up_never_writes_the_repo() {
    use std::os::unix::fs::PermissionsExt;
    let d = Dev::with(vec![]);
    let repo = d.repo(
        "shop",
        &[
            ("compose.yaml", "services: {}\n"),
            (".env", "SECRET=not-a-real-one\n"),
        ],
    );
    let before = snapshot(&repo);
    fs::set_permissions(&repo, fs::Permissions::from_mode(0o555)).unwrap();
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    let o2 = d.saiife(&["dev", "up"], &repo);
    fs::set_permissions(&repo, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&o2), 0, "{}", stderr(&o2));
    assert_eq!(snapshot(&repo), before);
}

#[cfg(unix)]
#[test]
fn failed_compose_up_writes_no_routes() {
    let d = Dev::with(vec![Rule::fail(
        "compose * up -d",
        1,
        "port is already allocated",
    )]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    let err = stderr(&o);
    assert!(err.starts_with("saiife dev: "), "{err}");
    assert!(err.contains("port is already allocated"), "{err}");
    assert!(!d.state.join("saiife/dev/proxy/dynamic/shop.toml").exists());
    assert!(!project_state_dir(&d, "shop").join("urls.json").exists());
    let state = read_json(&project_state_dir(&d, "shop").join("project.json"));
    assert!(state["last_up"].is_null(), "{state}");
    // The proxy is looked at again after the failure (best effort cleanup).
    let calls = d.calls();
    let at = calls.iter().position(|c| c.ends_with(" up -d")).unwrap();
    assert!(
        calls[at + 1..]
            .iter()
            .any(|c| c == "container inspect saiife-dev-proxy"),
        "{calls:?}"
    );
}

#[cfg(unix)]
#[test]
fn not_a_folder_is_a_plain_error() {
    let d = Dev::with(vec![]);
    let repo = shop_repo(&d);
    let nope = repo.join("nope");
    let o = d.saiife(&["dev", "up", nope.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("saiife dev: "), "{err}");
    assert!(err.contains("is not a folder"), "{err}");
    assert!(d.calls().is_empty(), "{:?}", d.calls());
    // A file is not a folder either.
    let file = repo.join("compose.yaml");
    let o = d.saiife(&["dev", "up", file.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("is not a folder"), "{}", stderr(&o));
    assert!(d.calls().is_empty(), "{:?}", d.calls());
}

#[cfg(unix)]
#[test]
fn no_port_anywhere_says_how_to_add_one() {
    let worker_only = r#"{
  "name": "shop",
  "services": { "worker": { "image": "busybox:1", "networks": { "default": null } } },
  "networks": { "default": { "name": "shop_default" } }
}"#;
    let d = Dev::with(vec![Rule::ok("*config --format json*", worker_only)]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    let quirks = d.config.join("saiife/dev/shop.toml");
    let want = format!(
        "No service has a port, so there is no URL. Set one in {}.\n",
        quirks.display()
    );
    assert!(out.contains(&want), "{out}");
    assert!(!out.contains("https://"), "{out}");
    assert_eq!(
        read_json(&project_state_dir(&d, "shop").join("urls.json")),
        serde_json::json!([])
    );
}

#[cfg(unix)]
#[test]
fn first_up_says_trust_the_ca_once() {
    let d = Dev::with(vec![]);
    let repo = shop_repo(&d);
    let line = "New local CA: run saiife dev ca to trust it.\n";
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).ends_with(line), "{}", stdout(&o));
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stdout(&o).contains("New local CA"), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn up_then_ls_shows_it_running_with_its_url() {
    let d = Dev::with(vec![ps_rule(&[
        ("a1", "saiife-shop-web-1", "shop", "running"),
        ("a2", "saiife-shop-worker-1", "shop", "running"),
    ])]);
    let repo = shop_repo(&d);
    let o = d.saiife(&["dev", "up", repo.to_str().unwrap()], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = ls_json(&d);
    let row = &v["projects"][0];
    assert_eq!(row["name"], "shop", "{v}");
    assert_eq!(row["state"], "running", "{v}");
    assert_eq!(
        row["urls"],
        serde_json::json!(["https://web.shop.localhost"])
    );
    assert_eq!(row["dir"], repo.to_str().unwrap());
    assert!(row["last_up"].is_string(), "{v}");
    let o = d.saiife(&["dev", "ls"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("https://web.shop.localhost"),
        "{}",
        stdout(&o)
    );
}

// ---- plan 24 Task 5: saiife dev gc ----

#[cfg(unix)]
const IMAGE_LINE: &str = "Dangling images are not touched: saiife removes only what it labelled saiife.managed=true. docker image prune removes them.";

/// `a` running, `b` stopped, `c` missing (its folder deleted), each with a
/// route file; `c` also has a leaf cert dir.
#[cfg(unix)]
fn seed_three(d: &Dev) {
    seed_up(d, "a");
    seed_up(d, "b");
    let c = seed_up(d, "c");
    fs::remove_dir_all(&c).unwrap();
    let tls = d.state.join("saiife/dev/tls/c");
    fs::create_dir_all(&tls).unwrap();
    fs::write(tls.join("cert.pem"), "x").unwrap();
}

#[cfg(unix)]
fn three_ps() -> Rule {
    ps_rule(&[
        ("a1", "saiife-a-web-1", "a", "running"),
        ("b1", "saiife-b-web-1", "b", "exited"),
        ("b2", "saiife-b-db-1", "b", "exited"),
        ("c1", "saiife-c-web-1", "c", "exited"),
        ("p1", "saiife-dev-proxy", "", "running"),
    ])
}

#[cfg(unix)]
#[test]
fn gc_removes_stopped_and_missing_keeps_running() {
    let d = Dev::with(vec![three_ps()]);
    seed_three(&d);
    let projects = d.state.join("saiife/dev/projects");
    let b_before = fs::read(projects.join("b/project.json")).unwrap();
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    for want in [
        "removed b (stopped)",
        "removed c (missing)",
        "kept a: still running",
    ] {
        assert!(out.lines().any(|l| l == want), "{want}\n{out}");
    }
    assert!(!projects.join("c").exists());
    assert!(!d.state.join("saiife/dev/tls/c").exists());
    assert!(projects.join("a/project.json").is_file());
    assert_eq!(fs::read(projects.join("b/project.json")).unwrap(), b_before);
    let dynamic = d.state.join("saiife/dev/proxy/dynamic");
    assert!(dynamic.join("a.toml").is_file());
    assert!(!dynamic.join("b.toml").exists());
    assert!(!dynamic.join("c.toml").exists());
    let calls = d.calls();
    assert!(calls.contains(&"rm b1 b2".to_string()), "{calls:?}");
    assert!(calls.contains(&"rm c1".to_string()), "{calls:?}");
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("rm ") && c.split(' ').any(|w| w == "a1" || w == "p1")),
        "{calls:?}"
    );
}

#[cfg(unix)]
#[test]
fn gc_removes_only_labelled() {
    let d = Dev::with(vec![
        three_ps(),
        Rule::ok(
            "network prune*",
            "Deleted Networks:\nsaiife-b_default\nsaiife-c_default\n",
        ),
        Rule::ok("volume ls*", "saiife-b_db\n"),
    ]);
    seed_three(&d);
    let o = d.saiife(&["dev", "gc", "--volumes", "--yes"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o)
            .lines()
            .any(|l| l == "removed unused saiife networks: saiife-b_default, saiife-c_default"),
        "{}",
        stdout(&o)
    );
    let calls = d.calls();
    // What the labelled listings returned.
    let listed = ["a1", "b1", "b2", "c1", "p1", "saiife-b_db"];
    let mut seen_listing = false;
    for c in &calls {
        if c.starts_with("ps -a --filter label=saiife.managed=true")
            || c.starts_with("volume ls -q --filter label=saiife.managed=true")
        {
            seen_listing = true;
        }
        if c == "rm -f saiife-dev-proxy" {
            continue;
        }
        let names: Option<&str> = c
            .strip_prefix("rm ")
            .or_else(|| c.strip_prefix("network rm "))
            .or_else(|| c.strip_prefix("volume rm "));
        if let Some(names) = names {
            assert!(seen_listing, "{c} before any labelled listing: {calls:?}");
            for n in names.split(' ') {
                assert!(listed.contains(&n), "{n} was never listed: {calls:?}");
            }
        }
        if c.contains("prune") {
            assert!(
                c.contains("--filter label=saiife.managed=true")
                    && c.contains("--filter label=saiife.dev.project"),
                "{c}"
            );
        }
        assert!(
            !(c.starts_with("network rm") && c.split(' ').any(|w| w == "saiife-dev")),
            "{c}"
        );
        assert!(!c.contains("image"), "{c}");
    }
    assert!(
        calls.iter().any(|c| c.contains("network prune")),
        "{calls:?}"
    );
}

#[cfg(unix)]
#[test]
fn gc_says_images_are_not_touched() {
    let d = Dev::with(vec![]);
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o).lines().last(),
        Some(IMAGE_LINE),
        "{}",
        stdout(&o)
    );

    let d = Dev::with(vec![three_ps()]);
    seed_three(&d);
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o).lines().last(),
        Some(IMAGE_LINE),
        "{}",
        stdout(&o)
    );
}

#[cfg(unix)]
#[test]
fn gc_volumes_without_yes_deletes_nothing() {
    let d = Dev::with(vec![three_ps(), Rule::ok("volume ls*", "saiife-b_db\n")]);
    seed_three(&d);
    let o = d.saiife(&["dev", "gc", "--volumes"], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains(
            "saiife dev: deleting volumes needs a yes. Run it in a terminal, or add --yes."
        ),
        "{}",
        stderr(&o)
    );
    let calls = d.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("rm") || c.contains(" rm") || c.contains("prune")),
        "{calls:?}"
    );
    assert!(d.state.join("saiife/dev/projects/c").is_dir());
    assert!(d.state.join("saiife/dev/proxy/dynamic/b.toml").is_file());
}

#[cfg(unix)]
#[test]
fn gc_volumes_with_yes() {
    let d = Dev::with(vec![Rule::ok("volume ls*", "v1\nv2\n")]);
    let o = d.saiife(&["dev", "gc", "--volumes", "--yes"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let calls = d.calls();
    let ls = calls
        .iter()
        .position(|c| c == "volume ls -q --filter label=saiife.managed=true --filter dangling=true")
        .unwrap_or_else(|| panic!("{calls:?}"));
    let rms: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c.starts_with("volume rm"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(rms.len(), 1, "{calls:?}");
    assert!(ls < rms[0], "{calls:?}");
    assert_eq!(calls[rms[0]], "volume rm v1 v2");
    // The removals of steps 3 to 5 come before the listing.
    let prune = calls
        .iter()
        .position(|c| c.contains("network prune"))
        .unwrap();
    assert!(prune < ls, "{calls:?}");
}

#[cfg(unix)]
#[test]
fn gc_removes_stale_route_files_only() {
    let d = Dev::with(vec![ps_rule(&[("a1", "saiife-a-web-1", "a", "running")])]);
    seed_up(&d, "a");
    let dynamic = d.state.join("saiife/dev/proxy/dynamic");
    fs::write(dynamic.join("ghost.toml"), "").unwrap();
    fs::write(dynamic.join("_tls.toml"), "").unwrap();
    fs::write(dynamic.join("Bad.toml"), "").unwrap();
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o)
            .lines()
            .any(|l| l == "removed stale routes: ghost"),
        "{}",
        stdout(&o)
    );
    assert!(!dynamic.join("ghost.toml").exists());
    assert!(dynamic.join("a.toml").is_file());
    assert!(dynamic.join("_tls.toml").is_file());
    assert!(dynamic.join("Bad.toml").is_file());
}

#[cfg(unix)]
#[test]
fn gc_docker_down_removes_nothing() {
    let d = Dev::with(vec![Rule::fail(
        "ps -a *",
        1,
        "Cannot connect to the Docker daemon",
    )]);
    seed_three(&d);
    let projects = d.state.join("saiife/dev/projects");
    let read_all = || -> Vec<Vec<u8>> {
        ["a", "b", "c"]
            .iter()
            .map(|p| fs::read(projects.join(p).join("project.json")).unwrap())
            .collect()
    };
    let before = read_all();
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains("docker did not answer, so nothing was removed"),
        "{}",
        stderr(&o)
    );
    assert_eq!(read_all(), before);
    assert_eq!(d.calls().len(), 1, "{:?}", d.calls());
    assert!(d.state.join("saiife/dev/proxy/dynamic/b.toml").is_file());
}

#[cfg(unix)]
#[test]
fn gc_counts_kept_volumes() {
    let d = Dev::with(vec![Rule::ok("volume ls*", "v1\nv2\nv3\n")]);
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o)
            .lines()
            .any(|l| l == "3 saiife volumes kept; saiife dev gc --volumes deletes them."),
        "{}",
        stdout(&o)
    );
    assert!(
        !d.calls().iter().any(|c| c.starts_with("volume rm")),
        "{:?}",
        d.calls()
    );

    let d = Dev::with(vec![]);
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stdout(&o).contains("volumes kept"), "{}", stdout(&o));
}

/// A corrupt `project.json` stops `gc` before any docker call: with one
/// project unreadable, gc cannot tell which labelled things are its.
#[cfg(unix)]
#[test]
fn gc_a_bad_state_file_is_one_clear_line() {
    let d = Dev::with(vec![three_ps()]);
    seed_three(&d);
    let pdir = d.state.join("saiife/dev/projects/other");
    fs::create_dir_all(&pdir).unwrap();
    fs::write(pdir.join("project.json"), "{not json").unwrap();
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("saiife dev: "), "{err}");
    assert!(d.calls().is_empty(), "{:?}", d.calls());
    assert!(d.state.join("saiife/dev/projects/c").is_dir());
}

#[cfg(unix)]
#[test]
fn gc_one_failing_project_does_not_stop_the_others() {
    let d = Dev::with(vec![three_ps(), Rule::fail("rm b1 b2", 1, "conflict")]);
    seed_three(&d);
    let o = d.saiife(&["dev", "gc"], d.root.path());
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert!(
        err.lines()
            .any(|l| l.starts_with("saiife dev: could not remove b: ")),
        "{err}"
    );
    assert!(
        stdout(&o).lines().any(|l| l == "removed c (missing)"),
        "{}",
        stdout(&o)
    );
    assert_eq!(stdout(&o).lines().last(), Some(IMAGE_LINE));
    assert!(d.calls().iter().any(|c| c.contains("network prune")));
    assert!(d.state.join("saiife/dev/proxy/dynamic/b.toml").is_file());
}
