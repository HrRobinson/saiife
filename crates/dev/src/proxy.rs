//! Traefik route files: one `<state>/proxy/dynamic/<project>.toml` per project.
//!
//! Output is built from `serde` structs held in `BTreeMap`s (fixed order), never
//! from strings. Traefik parses every file as a Go template and fails the whole
//! directory on one bad file, so everything is validated before anything is written.
use crate::certs::{write_atomic, CertPaths};
use crate::paths::DevPaths;
use crate::project::check_name;
use crate::rewrite::Route;
use crate::DevError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

pub(crate) fn dynamic_dir(paths: &DevPaths) -> PathBuf {
    paths.proxy_dir().join("dynamic")
}

#[derive(Serialize, Default)]
struct Doc {
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<Http>,
    tls: Tls,
}

#[derive(Serialize, Default)]
struct Http {
    routers: BTreeMap<String, Router>,
    services: BTreeMap<String, Service>,
    #[serde(
        rename = "serversTransports",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    servers_transports: BTreeMap<String, Transport>,
}

#[derive(Serialize)]
struct Router {
    rule: String,
    #[serde(rename = "entryPoints")]
    entry_points: Vec<&'static str>,
    service: String,
    tls: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Service {
    #[serde(rename = "loadBalancer")]
    load_balancer: LoadBalancer,
}

#[derive(Serialize)]
struct LoadBalancer {
    #[serde(rename = "serversTransport", skip_serializing_if = "Option::is_none")]
    servers_transport: Option<String>,
    servers: Vec<Server>,
}

#[derive(Serialize)]
struct Server {
    url: String,
}

#[derive(Serialize)]
struct Transport {
    #[serde(rename = "insecureSkipVerify")]
    insecure_skip_verify: bool,
}

#[derive(Serialize, Default)]
struct Tls {
    certificates: Vec<Certificate>,
}

#[derive(Serialize)]
struct Certificate {
    #[serde(rename = "certFile")]
    cert_file: String,
    #[serde(rename = "keyFile")]
    key_file: String,
}

fn bad(host: &str, reason: &'static str) -> DevError {
    DevError::RouteHost {
        host: host.to_string(),
        reason,
    }
}

/// `^[a-z0-9-]+$`
fn is_label(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `^[a-z0-9-]+(\.[a-z0-9-]+)*$`, and either `<p>.localhost` or one label under it.
fn check_host(host: &str, project: &str) -> Result<(), DevError> {
    if !host.split('.').all(is_label) {
        return Err(bad(host, "not a plain lowercase host name"));
    }
    let apex = format!("{project}.localhost");
    let ok = host == apex
        || host
            .strip_suffix(&format!(".{apex}"))
            .is_some_and(|label| !label.contains('.'));
    if ok {
        Ok(())
    } else {
        Err(bad(host, "not <project>.localhost or one label under it"))
    }
}

/// The server URL: a full `http(s)://` URL as it is, a bare `<host>:<port>` with
/// `<scheme>://` in front. Returns the URL and whether it is https.
fn server_url(r: &Route) -> Result<(String, bool), DevError> {
    let plain = !r.upstream.is_empty()
        && !r.upstream.contains("{{")
        && r.upstream
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'`' && b != b'"' && b != b'\\');
    if !plain {
        return Err(bad(&r.host, "upstream is not a plain URL"));
    }
    if r.upstream.starts_with("http://") {
        return Ok((r.upstream.clone(), false));
    }
    if r.upstream.starts_with("https://") {
        return Ok((r.upstream.clone(), true));
    }
    match r.upstream_scheme.as_str() {
        s @ ("http" | "https") => Ok((format!("{s}://{}", r.upstream), s == "https")),
        _ => Err(bad(&r.host, "upstream scheme is not http or https")),
    }
}

fn check_cert(paths: &DevPaths, project: &str, cert: &CertPaths) -> Result<(), DevError> {
    let dir = paths.state.join("tls").join(project);
    let inside = |p: &std::path::Path| p.file_name().is_some() && p.parent() == Some(dir.as_path());
    if inside(&cert.cert) && inside(&cert.key) {
        Ok(())
    } else {
        Err(bad(
            &format!("{project}.localhost"),
            "certificate is not in the project's tls directory",
        ))
    }
}

/// Writes `<state>/proxy/dynamic/<project>.toml`. Always renames a fresh file, even
/// for identical content, so that Traefik reloads (and re-reads a reissued leaf).
/// With no routes the file is removed.
pub fn write_routes(
    paths: &DevPaths,
    project: &str,
    routes: &[Route],
    cert: &CertPaths,
) -> Result<(), DevError> {
    check_name(project)?;
    check_cert(paths, project, cert)?;
    let transport = format!("{project}__insecure");
    let mut http = Http::default();
    for r in routes {
        check_host(&r.host, project)?;
        let label = r.host.split('.').next().unwrap_or_default();
        let n = if r.host == format!("{project}.localhost") {
            format!("{project}__apex")
        } else {
            format!("{project}_{label}")
        };
        if http.routers.contains_key(&n) {
            return Err(bad(&r.host, "two routes use the same host"));
        }
        let (url, https) = server_url(r)?;
        http.routers.insert(
            n.clone(),
            Router {
                rule: format!("Host(`{}`)", r.host),
                entry_points: vec!["websecure"],
                service: n.clone(),
                tls: BTreeMap::new(),
            },
        );
        if https {
            http.servers_transports.insert(
                transport.clone(),
                Transport {
                    insecure_skip_verify: true,
                },
            );
        }
        http.services.insert(
            n,
            Service {
                load_balancer: LoadBalancer {
                    servers_transport: https.then(|| transport.clone()),
                    servers: vec![Server { url }],
                },
            },
        );
    }
    if routes.is_empty() {
        return remove_routes(paths, project);
    }
    let doc = Doc {
        http: Some(http),
        tls: Tls {
            certificates: vec![Certificate {
                cert_file: format!("/saiife/tls/{project}/cert.pem"),
                key_file: format!("/saiife/tls/{project}/key.pem"),
            }],
        },
    };
    let text = toml::to_string(&doc).map_err(|e| DevError::Cert(e.to_string()))?;
    debug_assert!(!text.contains("{{"));
    let dir = dynamic_dir(paths);
    fs::create_dir_all(&dir).map_err(|source| DevError::Io {
        path: dir.clone(),
        source,
    })?;
    write_atomic(&dir.join(format!("{project}.toml")), text.as_bytes(), false)
}

/// Removes the project's route file (and with it its certificate entry).
pub fn remove_routes(paths: &DevPaths, project: &str) -> Result<(), DevError> {
    check_name(project)?;
    let f = dynamic_dir(paths).join(format!("{project}.toml"));
    match fs::remove_file(&f) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DevError::Io { path: f, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup() -> (tempfile::TempDir, DevPaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = DevPaths {
            state: d.path().join("state"),
            config: d.path().join("config"),
        };
        (d, paths)
    }

    fn certs(paths: &DevPaths, p: &str) -> CertPaths {
        let dir = paths.state.join("tls").join(p);
        CertPaths {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        }
    }

    fn route(service: &str, project: &str, upstream: &str, scheme: &str) -> Route {
        Route {
            host: format!("{service}.{project}.localhost"),
            upstream: upstream.into(),
            upstream_scheme: scheme.into(),
            service: service.into(),
        }
    }

    fn read(paths: &DevPaths, p: &str) -> toml::Value {
        let s = fs::read_to_string(dynamic_dir(paths).join(format!("{p}.toml"))).unwrap();
        toml::from_str(&s).unwrap()
    }

    fn two(paths: &DevPaths) -> Result<(), DevError> {
        let routes = [
            route("web", "shop", "web.shop:3000", "http"),
            route("api", "shop", "api.shop:8443", "https"),
        ];
        write_routes(paths, "shop", &routes, &certs(paths, "shop"))
    }

    fn only_files(paths: &DevPaths) -> Vec<String> {
        match fs::read_dir(dynamic_dir(paths)) {
            Ok(rd) => rd
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => vec![],
        }
    }

    #[test]
    fn routes_file_has_router_service_and_cert() {
        let (_d, paths) = setup();
        two(&paths).unwrap();
        let v = read(&paths, "shop");
        let r = &v["http"]["routers"]["shop_web"];
        assert_eq!(r["rule"].as_str(), Some("Host(`web.shop.localhost`)"));
        assert_eq!(r["entryPoints"].as_array().unwrap().len(), 1);
        assert_eq!(r["entryPoints"][0].as_str(), Some("websecure"));
        assert!(r["tls"].is_table());
        assert_eq!(r["service"].as_str(), Some("shop_web"));
        let web = &v["http"]["services"]["shop_web"]["loadBalancer"];
        assert_eq!(
            web["servers"][0]["url"].as_str(),
            Some("http://web.shop:3000")
        );
        assert!(web.get("serversTransport").is_none());
        let api = &v["http"]["services"]["shop_api"]["loadBalancer"];
        assert_eq!(
            api["servers"][0]["url"].as_str(),
            Some("https://api.shop:8443")
        );
        assert_eq!(api["serversTransport"].as_str(), Some("shop__insecure"));
        assert_eq!(
            v["http"]["serversTransports"]["shop__insecure"]["insecureSkipVerify"].as_bool(),
            Some(true)
        );
        let c = &v["tls"]["certificates"][0];
        assert_eq!(c["certFile"].as_str(), Some("/saiife/tls/shop/cert.pem"));
        assert_eq!(c["keyFile"].as_str(), Some("/saiife/tls/shop/key.pem"));
    }

    #[test]
    fn no_transport_when_all_http() {
        let (_d, paths) = setup();
        let routes = [route("web", "shop", "web.shop:3000", "http")];
        write_routes(&paths, "shop", &routes, &certs(&paths, "shop")).unwrap();
        let v = read(&paths, "shop");
        assert!(v["http"].get("serversTransports").is_none());
    }

    #[test]
    fn full_url_upstream_is_kept() {
        let (_d, paths) = setup();
        let routes = [route("web", "shop", "http://web.shop:3000", "http")];
        write_routes(&paths, "shop", &routes, &certs(&paths, "shop")).unwrap();
        let v = read(&paths, "shop");
        assert_eq!(
            v["http"]["services"]["shop_web"]["loadBalancer"]["servers"][0]["url"].as_str(),
            Some("http://web.shop:3000")
        );
    }

    #[test]
    fn bad_hosts_write_nothing() {
        for host in [
            "a.b.shop.localhost",
            "web.other.localhost",
            "we`b.shop.localhost",
            "Web.shop.localhost",
            "{{x}}.shop.localhost",
        ] {
            let (_d, paths) = setup();
            let mut r = route("web", "shop", "web.shop:3000", "http");
            r.host = host.into();
            let e = write_routes(&paths, "shop", &[r], &certs(&paths, "shop")).unwrap_err();
            assert!(matches!(e, DevError::RouteHost { .. }), "{host}: {e}");
            assert!(only_files(&paths).is_empty(), "{host}");
        }
        let (_d, paths) = setup();
        let routes = [
            route("web", "shop", "web.shop:3000", "http"),
            route("web", "shop", "web.shop:3001", "http"),
        ];
        let e = write_routes(&paths, "shop", &routes, &certs(&paths, "shop")).unwrap_err();
        assert!(matches!(e, DevError::RouteHost { .. }));
        assert!(only_files(&paths).is_empty());
    }

    #[test]
    fn apex_host_is_allowed() {
        let (_d, paths) = setup();
        let mut r = route("web", "shop", "web.shop:3000", "http");
        r.host = "shop.localhost".into();
        write_routes(&paths, "shop", &[r], &certs(&paths, "shop")).unwrap();
        let v = read(&paths, "shop");
        assert_eq!(
            v["http"]["routers"]["shop__apex"]["rule"].as_str(),
            Some("Host(`shop.localhost`)")
        );
    }

    #[test]
    fn cert_outside_project_is_refused() {
        let (_d, paths) = setup();
        let routes = [route("web", "shop", "web.shop:3000", "http")];
        let other = certs(&paths, "other");
        let e = write_routes(&paths, "shop", &routes, &other).unwrap_err();
        match e {
            DevError::RouteHost { reason, .. } => {
                assert_eq!(reason, "certificate is not in the project's tls directory")
            }
            e => panic!("{e}"),
        }
        let outside = CertPaths {
            cert: paths.state.join("ca").join("ca.pem"),
            key: paths.state.join("ca").join("ca-key.pem"),
        };
        assert!(write_routes(&paths, "shop", &routes, &outside).is_err());
        assert!(only_files(&paths).is_empty());
    }

    #[test]
    fn bad_project_name_is_refused() {
        let (_d, paths) = setup();
        let e = write_routes(&paths, "Shop", &[], &certs(&paths, "Shop")).unwrap_err();
        assert!(matches!(e, DevError::BadProjectName(_)));
        assert!(matches!(
            remove_routes(&paths, "../x").unwrap_err(),
            DevError::BadProjectName(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_always_renames() {
        use std::os::unix::fs::MetadataExt;
        let (_d, paths) = setup();
        two(&paths).unwrap();
        let f = dynamic_dir(&paths).join("shop.toml");
        let a = fs::metadata(&f).unwrap().ino();
        two(&paths).unwrap();
        let b = fs::metadata(&f).unwrap().ino();
        assert_ne!(a, b);
        assert_eq!(only_files(&paths), vec!["shop.toml".to_string()]);
    }

    #[test]
    fn empty_routes_remove_the_file() {
        let (_d, paths) = setup();
        two(&paths).unwrap();
        write_routes(&paths, "shop", &[], &certs(&paths, "shop")).unwrap();
        assert!(only_files(&paths).is_empty());
    }

    #[test]
    fn remove_routes_is_idempotent() {
        let (_d, paths) = setup();
        remove_routes(&paths, "shop").unwrap();
        two(&paths).unwrap();
        remove_routes(&paths, "shop").unwrap();
        remove_routes(&paths, "shop").unwrap();
        assert!(only_files(&paths).is_empty());
    }

    #[test]
    fn no_template_braces_in_output() {
        let (_d, paths) = setup();
        two(&paths).unwrap();
        let s = fs::read_to_string(dynamic_dir(&paths).join("shop.toml")).unwrap();
        assert!(!s.contains("{{"));
    }

    #[test]
    fn compose_service_names_are_accepted() {
        let (_d, paths) = setup();
        let mut r = route("my_db", "shop", "my-db.shop:5432", "http");
        r.host = "my-db.shop.localhost".into();
        write_routes(&paths, "shop", &[r], &certs(&paths, "shop")).unwrap();
        let v = read(&paths, "shop");
        assert!(v["http"]["routers"].get("shop_my-db").is_some());
    }

    #[test]
    fn names_do_not_collide_across_projects() {
        let (_d, paths) = setup();
        let mut a = route("x", "a", "x.a:1", "http");
        a.host = "b-c.a.localhost".into();
        let mut b = route("x", "a-b", "x.a-b:1", "http");
        b.host = "c.a-b.localhost".into();
        write_routes(&paths, "a", &[a], &certs(&paths, "a")).unwrap();
        write_routes(&paths, "a-b", &[b], &certs(&paths, "a-b")).unwrap();
        let ra = read(&paths, "a")["http"]["routers"]
            .as_table()
            .unwrap()
            .clone();
        let rb = read(&paths, "a-b")["http"]["routers"]
            .as_table()
            .unwrap()
            .clone();
        assert!(ra.keys().all(|k| !rb.contains_key(k)));
    }
}
