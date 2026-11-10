//! Per-project quirks from the config dir.
use crate::paths::DevPaths;
use crate::project::{check_name, dns_label};
use crate::DevError;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Settings for one compose service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceQuirk {
    pub port: Option<u16>,
    pub scheme: Option<String>,
    #[serde(default)]
    pub skip: bool,
    pub host: Option<String>,
}

/// The whole `<project>.toml` file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quirks {
    #[serde(default)]
    pub services: BTreeMap<String, ServiceQuirk>,
}

/// Parse and check a quirks file. Errors name the service.
pub fn parse(text: &str) -> Result<Quirks, String> {
    // Range-check ports on the raw table first, so the error can name the service.
    let raw: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    if let Some(toml::Value::Table(services)) = raw.get("services") {
        for (name, svc) in services {
            if let Some(toml::Value::Integer(p)) = svc.get("port") {
                if !(1..=65535).contains(p) {
                    return Err(format!("services.{name}: port {p} is not in 1..=65535"));
                }
            }
        }
    }
    let q: Quirks = toml::from_str(text).map_err(|e| e.to_string())?;
    for (name, s) in &q.services {
        if s.port == Some(0) {
            return Err(format!("services.{name}: port must not be 0"));
        }
        if let Some(sc) = &s.scheme {
            if sc != "http" && sc != "https" {
                return Err(format!(
                    "services.{name}: scheme must be \"http\" or \"https\", not {sc:?}"
                ));
            }
        }
        if let Some(h) = &s.host {
            if dns_label(h).as_deref() != Some(h.as_str()) {
                return Err(format!(
                    "services.{name}: host {h:?} must be a DNS label (lowercase letters, digits, -)"
                ));
            }
        }
    }
    Ok(q)
}

/// Load `<config>/<project>.toml`. A missing file means no quirks.
pub fn load(paths: &DevPaths, project: &str) -> Result<Quirks, DevError> {
    check_name(project)?;
    let path = paths.quirks_file(project);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Quirks::default()),
        Err(source) => return Err(DevError::Io { path, source }),
    };
    parse(&text).map_err(|msg| DevError::Quirks { path, msg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &std::path::Path) -> DevPaths {
        DevPaths {
            state: dir.join("state"),
            config: dir.join("config"),
        }
    }

    #[test]
    fn parses_the_documented_example() {
        let q = parse(
            "[services.web]\nport = 3000\nscheme = \"https\"\nhost = \"app\"\n[services.worker]\nskip = true\n",
        )
        .unwrap();
        assert_eq!(
            q.services["web"],
            ServiceQuirk {
                port: Some(3000),
                scheme: Some("https".into()),
                host: Some("app".into()),
                skip: false
            }
        );
        assert!(q.services["worker"].skip);
    }

    #[test]
    fn unknown_key_is_an_error() {
        assert!(parse("[services.web]\nprot = 3000")
            .unwrap_err()
            .contains("prot"));
        assert!(parse("[service.web]\nport = 3000")
            .unwrap_err()
            .contains("service"));
    }

    #[test]
    fn bad_values_are_errors() {
        for body in [
            "port = 0",
            "port = 70000",
            "scheme = \"ftp\"",
            "host = \"App.x\"",
        ] {
            let e = parse(&format!("[services.web]\n{body}")).unwrap_err();
            assert!(e.contains("web"), "{body}: {e}");
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(load(&paths(d.path()), "shop").unwrap(), Quirks::default());
    }

    #[test]
    fn load_reports_the_path() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        std::fs::create_dir_all(&p.config).unwrap();
        std::fs::write(p.quirks_file("shop"), "[services.web]\nport = 0").unwrap();
        match load(&p, "shop") {
            Err(DevError::Quirks { path, .. }) => assert_eq!(path, p.quirks_file("shop")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn load_rejects_a_bad_project_name() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(&paths(d.path()), "../shop"),
            Err(DevError::BadProjectName(_))
        ));
    }
}
