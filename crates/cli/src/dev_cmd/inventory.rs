//! `saiife dev ls` (plan 24 Task 3), and the inventory `gc` shares.
//!
//! The inventory joins two sources: the project state files (which folder, when
//! last up, which URLs) and one `docker ps -a` over the labelled containers
//! (which are running). A project in either source is a row.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use saiife_dev::docker::{run_ok, Docker};
use saiife_dev::labels::{MANAGED, PROJECT, PROXY_CONTAINER};
use saiife_dev::paths::DevPaths;
use saiife_dev::project;

use crate::text::sanitize;

/// The `--format` of the labelled container listing.
pub(crate) fn ps_format() -> String {
    format!("{{{{.ID}}}}\t{{{{.Names}}}}\t{{{{.Label \"{PROJECT}\"}}}}\t{{{{.State}}}}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Container {
    pub id: String,
    pub name: String,
    pub project: String,
    pub running: bool,
}

/// One container per line with four tab-separated fields; other lines are skipped.
pub(crate) fn parse_ps(stdout: &str) -> Vec<Container> {
    stdout
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 4 {
                return None;
            }
            Some(Container {
                id: f[0].to_string(),
                name: f[1].to_string(),
                project: f[2].to_string(),
                running: f[3].trim() == "running",
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Running,
    Partial,
    Stopped,
    Missing,
    Unknown,
}

impl State {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            State::Running => "running",
            State::Partial => "partial",
            State::Stopped => "stopped",
            State::Missing => "missing",
            State::Unknown => "unknown",
        }
    }
}

/// The state table of plan 24 (P3), for a docker that answered.
pub(crate) fn classify(folder_exists: bool, running: usize, total: usize) -> State {
    if total > 0 && running == total {
        State::Running
    } else if running > 0 {
        State::Partial
    } else if folder_exists {
        State::Stopped
    } else {
        State::Missing
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub name: String,
    pub dir: Option<PathBuf>,
    pub urls: Vec<String>,
    pub state: State,
    pub last_up: Option<String>,
    pub running: usize,
    pub total: usize,
    pub containers: Vec<Container>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proxy {
    Running,
    Stopped,
    Absent,
    Unknown,
}

impl Proxy {
    fn as_str(self) -> &'static str {
        match self {
            Proxy::Running => "running",
            Proxy::Stopped => "stopped",
            Proxy::Absent => "absent",
            Proxy::Unknown => "unknown",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Inventory {
    pub rows: Vec<Row>,
    pub proxy: Proxy,
    pub docker_error: Option<String>,
}

fn read_urls(paths: &DevPaths, name: &str) -> Vec<String> {
    std::fs::read_to_string(paths.project_dir(name).join("urls.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
        .unwrap_or_default()
}

/// Every project from state and labels. A state error is fatal; a Docker
/// error leaves every state `Unknown` and is named in `docker_error`.
pub(crate) fn inventory(d: &dyn Docker, paths: &DevPaths) -> Result<Inventory, String> {
    let projects = project::list(paths).map_err(|e| e.to_string())?;
    let filter = format!("label={MANAGED}=true");
    let format = ps_format();
    let listed = run_ok(d, &["ps", "-a", "--filter", &filter, "--format", &format]);
    let (containers, docker_error) = match listed {
        Ok(out) => (parse_ps(&String::from_utf8_lossy(&out)), None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let known = docker_error.is_none();
    let proxy = if !known {
        Proxy::Unknown
    } else {
        match containers.iter().find(|c| c.name == PROXY_CONTAINER) {
            Some(c) if c.running => Proxy::Running,
            Some(_) => Proxy::Stopped,
            None => Proxy::Absent,
        }
    };
    let mut by_project: BTreeMap<String, Vec<Container>> = BTreeMap::new();
    for c in containers.into_iter().filter(|c| !c.project.is_empty()) {
        by_project.entry(c.project.clone()).or_default().push(c);
    }
    let mut rows = Vec::new();
    for p in projects {
        let containers = by_project.remove(&p.name).unwrap_or_default();
        rows.push(row(
            p.name.clone(),
            Some(p.dir.clone()),
            read_urls(paths, &p.name),
            p.last_up.clone(),
            containers,
            known,
        ));
    }
    // What is left carries a project label with no state: an orphan.
    for (name, containers) in by_project {
        rows.push(row(name, None, Vec::new(), None, containers, known));
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Inventory {
        rows,
        proxy,
        docker_error,
    })
}

fn row(
    name: String,
    dir: Option<PathBuf>,
    urls: Vec<String>,
    last_up: Option<String>,
    containers: Vec<Container>,
    docker_known: bool,
) -> Row {
    let running = containers.iter().filter(|c| c.running).count();
    let total = containers.len();
    let state = if docker_known {
        let exists = dir.as_ref().is_some_and(|d| d.is_dir());
        classify(exists, running, total)
    } else {
        State::Unknown
    };
    Row {
        name,
        dir,
        urls,
        state,
        last_up,
        running,
        total,
        containers,
    }
}

/// Lists every environment, as a table or as JSON.
pub(crate) fn ls(d: &dyn Docker, paths: &DevPaths, json: bool) -> ExitCode {
    let inv = match inventory(d, paths) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("saiife dev: {}", sanitize(e.trim_end()));
            return ExitCode::from(1);
        }
    };
    if json {
        print_json(&inv);
    } else {
        print_table(&inv);
    }
    match &inv.docker_error {
        Some(e) => {
            eprintln!(
                "saiife dev: docker did not answer, so states are unknown: {}",
                sanitize(e.trim_end())
            );
            ExitCode::from(1)
        }
        None => ExitCode::SUCCESS,
    }
}

fn print_json(inv: &Inventory) {
    let projects: Vec<_> = inv
        .rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "dir": r.dir.as_ref().map(|d| d.to_string_lossy().into_owned()),
                "urls": r.urls,
                "state": r.state.as_str(),
                "last_up": r.last_up,
                "containers": { "running": r.running, "total": r.total },
            })
        })
        .collect();
    let doc = serde_json::json!({ "projects": projects, "proxy": inv.proxy.as_str() });
    outln!("{doc}");
}

fn print_table(inv: &Inventory) {
    if inv.rows.is_empty() {
        outln!("No saiife dev projects yet. Run saiife dev up in a folder with a compose file.");
    } else {
        let cells: Vec<[String; 4]> = inv
            .rows
            .iter()
            .map(|r| {
                [
                    sanitize(&r.name),
                    r.state.as_str().to_string(),
                    r.last_up
                        .as_deref()
                        .map(sanitize)
                        .unwrap_or_else(|| "-".into()),
                    r.dir
                        .as_ref()
                        .map(|d| sanitize(&d.display().to_string()))
                        .unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        let head = ["PROJECT", "STATE", "LAST UP", "DIR"].map(String::from);
        let widths: Vec<usize> = (0..3)
            .map(|i| {
                std::iter::once(&head)
                    .chain(cells.iter())
                    .map(|c| c[i].chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let line = |c: &[String; 4]| {
            let mut s = String::new();
            for i in 0..3 {
                s.push_str(&c[i]);
                s.push_str(&" ".repeat(widths[i] - c[i].chars().count() + 2));
            }
            s.push_str(&c[3]);
            s
        };
        outln!("{}", line(&head));
        for (r, c) in inv.rows.iter().zip(&cells) {
            outln!("{}", line(c));
            if matches!(r.state, State::Running | State::Partial) {
                for u in &r.urls {
                    outln!("{}{}", " ".repeat(widths[0] + 2), sanitize(u));
                }
            }
        }
    }
    outln!("proxy: {}", inv.proxy.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ps_reads_four_fields() {
        let out = "a1\tweb-1\tshop\trunning\nb2\tdb-1\tshop\texited\nbad\tline\tonly3\nc3\tproxy\t\trunning\n";
        let cs = parse_ps(out);
        assert_eq!(cs.len(), 3);
        assert_eq!(
            cs[0],
            Container {
                id: "a1".into(),
                name: "web-1".into(),
                project: "shop".into(),
                running: true
            }
        );
        assert!(!cs[1].running);
        assert_eq!(cs[2].project, "");
    }

    #[test]
    fn ps_format_names_the_project_label() {
        assert_eq!(
            ps_format(),
            "{{.ID}}\t{{.Names}}\t{{.Label \"saiife.dev.project\"}}\t{{.State}}"
        );
    }

    #[test]
    fn classify_follows_the_table() {
        for folder in [true, false] {
            assert_eq!(classify(folder, 2, 2), State::Running);
            assert_eq!(classify(folder, 1, 2), State::Partial);
        }
        assert_eq!(classify(true, 0, 2), State::Stopped);
        assert_eq!(classify(true, 0, 0), State::Stopped);
        assert_eq!(classify(false, 0, 2), State::Missing);
        assert_eq!(classify(false, 0, 0), State::Missing);
        assert_eq!(State::Partial.as_str(), "partial");
        assert_eq!(State::Unknown.as_str(), "unknown");
    }
}
