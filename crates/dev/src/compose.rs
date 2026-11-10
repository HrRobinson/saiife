//! Reading a repo's compose model.

use crate::docker::{run_ok, Docker};
use crate::DevError;
use std::path::Path;

/// One `ports` entry in the long syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    pub target: u16,
    pub published: Option<u16>,
    pub protocol: String,
}

/// What `rewrite` needs to know about one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub ports: Vec<PublishedPort>,
    pub expose: Vec<u16>,
}

/// The merged, normalized model, and the parts of it we look at.
#[derive(Debug, Clone)]
pub struct ComposeModel {
    pub raw: serde_json::Value,
    /// Sorted by name.
    pub services: Vec<ServiceInfo>,
}

const BASE_FILES: [&str; 4] = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
];
const OVERRIDE_FILES: [&str; 4] = [
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
];

fn bad(svc: &str, msg: &str) -> DevError {
    DevError::ComposeJson(format!("service {svc}: {msg}"))
}

/// The start of a port or `start-end` range, from a number or a string.
fn port_of(v: &serde_json::Value) -> Option<u16> {
    let n = match v {
        serde_json::Value::Number(n) => n.as_u64()?,
        serde_json::Value::String(s) => s.split('-').next()?.trim().parse().ok()?,
        _ => return None,
    };
    u16::try_from(n).ok().filter(|p| *p != 0)
}

fn parse_port(svc: &str, v: &serde_json::Value) -> Result<PublishedPort, DevError> {
    let o = v
        .as_object()
        .ok_or_else(|| bad(svc, "a ports entry is not an object"))?;
    let target = o
        .get("target")
        .and_then(port_of)
        .ok_or_else(|| bad(svc, "a ports entry has no valid target (1-65535)"))?;
    let published = match o.get("published") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if s.is_empty() => None,
        Some(p) => Some(
            port_of(p).ok_or_else(|| bad(svc, "a ports entry has an invalid published port"))?,
        ),
    };
    let protocol = o
        .get("protocol")
        .and_then(|p| p.as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("tcp")
        .to_string();
    Ok(PublishedPort {
        target,
        published,
        protocol,
    })
}

fn parse_expose(svc: &str, v: &serde_json::Value) -> Result<Vec<u16>, DevError> {
    let list = v
        .as_array()
        .ok_or_else(|| bad(svc, "expose is not a list"))?;
    let mut out = Vec::new();
    for e in list {
        let (spec, proto) = match e {
            serde_json::Value::String(s) => match s.split_once('/') {
                Some((a, p)) => (serde_json::Value::from(a), p),
                None => (e.clone(), "tcp"),
            },
            _ => (e.clone(), "tcp"),
        };
        let p = port_of(&spec).ok_or_else(|| bad(svc, "an expose entry is not a port"))?;
        if proto != "udp" {
            out.push(p);
        }
    }
    Ok(out)
}

/// Parses the output of `docker compose config --format json`.
pub fn parse_model(json: &[u8]) -> Result<ComposeModel, DevError> {
    let raw: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| DevError::ComposeJson(format!("not valid JSON: {e}")))?;
    let top = raw
        .as_object()
        .ok_or_else(|| DevError::ComposeJson("not a JSON object".into()))?;
    let svcs = match top.get("services") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_object()
                .ok_or_else(|| DevError::ComposeJson("services is not an object".into()))?,
        ),
    };
    let mut services = Vec::new();
    for (name, def) in svcs.into_iter().flatten() {
        let mut ports = Vec::new();
        let mut expose = Vec::new();
        if let Some(def) = def.as_object() {
            match def.get("ports") {
                None | Some(serde_json::Value::Null) => {}
                Some(serde_json::Value::Array(a)) => {
                    for p in a {
                        ports.push(parse_port(name, p)?);
                    }
                }
                Some(_) => return Err(bad(name, "ports is not a list")),
            }
            match def.get("expose") {
                None | Some(serde_json::Value::Null) => {}
                Some(v) => expose = parse_expose(name, v)?,
            }
        }
        services.push(ServiceInfo {
            name: name.clone(),
            ports,
            expose,
        });
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ComposeModel { raw, services })
}

fn utf8(p: &Path) -> Result<&str, DevError> {
    p.to_str()
        .ok_or_else(|| DevError::NonUtf8Path(p.to_path_buf()))
}

/// Reads the merged compose model of the compose files in `dir`.
pub fn read_config(d: &dyn Docker, dir: &Path) -> Result<ComposeModel, DevError> {
    let find = |names: &[&str]| names.iter().map(|n| dir.join(n)).find(|p| p.is_file());
    let base = find(&BASE_FILES).ok_or_else(|| DevError::NoComposeFile {
        dir: dir.to_path_buf(),
    })?;
    let over = find(&OVERRIDE_FILES);
    let mut args = vec![
        "compose",
        "--project-directory",
        utf8(dir)?,
        "-f",
        utf8(&base)?,
    ];
    if let Some(o) = &over {
        args.push("-f");
        args.push(utf8(o)?);
    }
    args.extend(["config", "--format", "json"]);
    match run_ok(d, &args) {
        Ok(stdout) => parse_model(&stdout),
        Err(DevError::Docker { stderr, .. })
            if stderr.contains("'compose' is not a docker command")
                || stderr.contains("unknown command: docker compose") =>
        {
            Err(DevError::ComposeMissing)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::{FakeDocker, Output};

    const V2: &[u8] = include_bytes!("../tests/fixtures/config-v2.json");
    const V1: &[u8] = include_bytes!("../tests/fixtures/config-v1.json");

    fn svc<'a>(m: &'a ComposeModel, n: &str) -> &'a ServiceInfo {
        m.services.iter().find(|s| s.name == n).unwrap()
    }

    #[test]
    fn parses_current_shape() {
        let m = parse_model(V2).unwrap();
        let web = svc(&m, "web");
        assert_eq!(
            web.ports,
            vec![
                PublishedPort {
                    target: 3000,
                    published: Some(8080),
                    protocol: "tcp".into()
                },
                PublishedPort {
                    target: 4000,
                    published: Some(8000),
                    protocol: "tcp".into()
                },
                PublishedPort {
                    target: 5000,
                    published: None,
                    protocol: "tcp".into()
                },
            ]
        );
        assert_eq!(web.expose, vec![9000, 9001]);
        assert_eq!(svc(&m, "db").expose, vec![5432]);
        assert!(svc(&m, "agent").ports.is_empty());
        assert!(m.raw["networks"]["edge"]["external"].as_bool().unwrap());
    }

    #[test]
    fn parses_v1_shape() {
        let m = parse_model(V1).unwrap();
        assert_eq!(
            svc(&m, "web").ports,
            vec![PublishedPort {
                target: 3000,
                published: Some(8080),
                protocol: "tcp".into()
            }]
        );
    }

    #[test]
    fn lenient_numbers_and_defaults() {
        let m = parse_model(
            br#"{"services":{"a":{"ports":[{"target":"80","published":""}],"expose":[3000,"3001/tcp"]}}}"#,
        )
        .unwrap();
        let a = svc(&m, "a");
        assert_eq!(a.ports[0].target, 80);
        assert_eq!(a.ports[0].published, None);
        assert_eq!(a.ports[0].protocol, "tcp");
        assert_eq!(a.expose, vec![3000, 3001]);
    }

    #[test]
    fn services_are_sorted() {
        let m = parse_model(br#"{"services":{"z":{},"a":{},"m":{}}}"#).unwrap();
        let names: Vec<_> = m.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "m", "z"]);
    }

    #[test]
    fn bad_shapes_are_compose_json() {
        assert!(matches!(parse_model(b"[]"), Err(DevError::ComposeJson(_))));
        assert!(matches!(
            parse_model(b"nope"),
            Err(DevError::ComposeJson(_))
        ));
        assert!(matches!(
            parse_model(br#"{"services": []}"#),
            Err(DevError::ComposeJson(_))
        ));
        match parse_model(br#"{"services":{"web":{"ports":["8080:80"]}}}"#) {
            Err(DevError::ComposeJson(m)) => assert!(m.contains("web"), "{m}"),
            other => panic!("{other:?}"),
        }
        for bad in [
            r#"{"ports":[{"published":"1"}]}"#,
            r#"{"ports":[{"target":0}]}"#,
            r#"{"ports":[{"target":70000}]}"#,
        ] {
            let j = format!(r#"{{"services":{{"api":{bad}}}}}"#);
            match parse_model(j.as_bytes()) {
                Err(DevError::ComposeJson(m)) => assert!(m.contains("api"), "{m}"),
                other => panic!("{other:?}"),
            }
        }
    }

    fn dir_with(files: &[&str]) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        for f in files {
            std::fs::write(t.path().join(f), "").unwrap();
        }
        t
    }

    fn s(p: std::path::PathBuf) -> String {
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn read_config_args() {
        let t = dir_with(&["compose.yaml", "compose.override.yml"]);
        let f = FakeDocker::new();
        f.on(&["compose"], Output::ok(V2));
        let m = read_config(&f, t.path()).unwrap();
        assert_eq!(m.services.len(), 3);
        let calls = f.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].stdin, None);
        let d = s(t.path().to_path_buf());
        assert_eq!(
            calls[0].args,
            vec![
                "compose".to_string(),
                "--project-directory".into(),
                d,
                "-f".into(),
                s(t.path().join("compose.yaml")),
                "-f".into(),
                s(t.path().join("compose.override.yml")),
                "config".into(),
                "--format".into(),
                "json".into(),
            ]
        );
    }

    #[test]
    fn base_file_order() {
        let t = dir_with(&["docker-compose.yml", "compose.yml"]);
        let f = FakeDocker::new();
        f.on(&["compose"], Output::ok(V2));
        read_config(&f, t.path()).unwrap();
        let a = &f.calls()[0].args;
        assert_eq!(a.iter().filter(|x| *x == "-f").count(), 1);
        assert!(a.contains(&s(t.path().join("compose.yml"))));
    }

    #[test]
    fn no_compose_file() {
        let t = dir_with(&[]);
        let f = FakeDocker::new();
        assert!(matches!(
            read_config(&f, t.path()),
            Err(DevError::NoComposeFile { .. })
        ));
        assert!(f.calls().is_empty());
    }

    #[test]
    fn compose_plugin_missing_is_named() {
        let t = dir_with(&["compose.yaml"]);
        let f = FakeDocker::new();
        f.on(
            &["compose"],
            Output::fail(1, "docker: 'compose' is not a docker command."),
        );
        assert!(matches!(
            read_config(&f, t.path()),
            Err(DevError::ComposeMissing)
        ));
    }

    #[test]
    fn config_error_keeps_compose_stderr() {
        let t = dir_with(&["compose.yaml"]);
        let f = FakeDocker::new();
        f.on(
            &["compose"],
            Output::fail(15, "services.web Additional property foo is not allowed"),
        );
        match read_config(&f, t.path()) {
            Err(DevError::Docker { status, stderr, .. }) => {
                assert_eq!(status, 15);
                assert_eq!(
                    stderr,
                    "services.web Additional property foo is not allowed"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stderr_warning_is_ignored() {
        let t = dir_with(&["compose.yaml"]);
        let f = FakeDocker::new();
        let mut out = Output::ok(V2);
        out.stderr = b"the attribute `version` is obsolete".to_vec();
        f.on(&["compose"], out);
        assert!(read_config(&f, t.path()).is_ok());
    }
}
