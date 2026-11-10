//! Traefik route files: one `<state>/proxy/dynamic/<project>.toml` per project.
//!
//! Output is built from `serde` structs held in `BTreeMap`s (fixed order), never
//! from strings. Traefik parses every file as a Go template and fails the whole
//! directory on one bad file, so everything is validated before anything is written.
use crate::certs::{tls_dir, write_atomic, CertPaths};
use crate::docker::{run_ok, Docker, Output};
use crate::labels::{MANAGED, NETWORK, PROXY_CONTAINER};
use crate::paths::DevPaths;
use crate::project::check_name;
use crate::rewrite::Route;
use crate::DevError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Label naming a resource's role (`proxy` or `network`). Role-labelled
/// resources carry no project label.
pub const ROLE: &str = "saiife.dev.role";
/// Reserved for shared TLS options; saiife never writes it, and route
/// handling ignores it. A leading `_` is never a valid project name.
pub const TLS_FILE: &str = "_tls.toml";

/// What binding a loopback port said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Free,
    InUse,
    Unknown,
}

/// Binds `127.0.0.1:<port>` and drops the listener at once.
/// In debug builds `SAIIFE_DEV_SKIP_PORT_BIND=1` answers `Unknown` unbound.
pub(crate) fn probe_bind(port: u16) -> Probe {
    #[cfg(debug_assertions)]
    if std::env::var_os("SAIIFE_DEV_SKIP_PORT_BIND").is_some_and(|v| v == "1") {
        return Probe::Unknown;
    }
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => Probe::Free,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => Probe::InUse,
        Err(_) => Probe::Unknown,
    }
}

fn first_name(out: &[u8]) -> Option<String> {
    String::from_utf8_lossy(out)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Checks that 127.0.0.1:80 and :443 are free, or already held by our proxy.
pub fn preflight_ports(d: &dyn Docker) -> Result<(), DevError> {
    preflight_ports_with(d, &probe_bind)
}

pub fn preflight_ports_with(d: &dyn Docker, probe: &dyn Fn(u16) -> Probe) -> Result<(), DevError> {
    let managed = format!("label={MANAGED}=true");
    let role = format!("label={ROLE}=proxy");
    let up = run_ok(
        d,
        &[
            "ps",
            "--filter",
            &managed,
            "--filter",
            &role,
            "--format",
            "{{.Names}}",
        ],
    )?;
    // Compare names exactly: docker's name filter is a substring match.
    if String::from_utf8_lossy(&up)
        .lines()
        .any(|l| l.trim() == PROXY_CONTAINER)
    {
        return Ok(());
    }
    for port in [80u16, 443] {
        let state = probe(port);
        if state == Probe::Free {
            continue;
        }
        let publish = format!("publish={port}");
        let holder = d
            .run(
                &["ps", "--filter", &publish, "--format", "{{.Names}}"],
                None,
            )
            .ok()
            .filter(|o| o.status == 0)
            .and_then(|o| first_name(&o.stdout));
        if state == Probe::InUse || holder.is_some() {
            return Err(DevError::PortBusy { port, holder });
        }
    }
    Ok(())
}

/// Replays one recorded `Output`, so a failed call becomes `run_ok`'s
/// `DevError::Docker` (trimmed, capped stderr) without running docker again.
struct Replay(std::sync::Mutex<Option<Output>>);

impl Docker for Replay {
    fn run(&self, _args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, DevError> {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Ok(slot.take().unwrap_or_else(|| Output::fail(-1, "")))
    }
}

/// The `DevError::Docker` for a failed `out` of `docker <args>`.
fn docker_error(args: &[&str], out: Output) -> DevError {
    let status = out.status;
    let replay = Replay(std::sync::Mutex::new(Some(out)));
    match run_ok(&replay, args) {
        Err(e) => e,
        Ok(_) => DevError::Docker {
            args: args.iter().map(|a| a.to_string()).collect(),
            status,
            stderr: String::new(),
        },
    }
}

/// `None` when the network is missing, else whether saiife created it.
fn network_is_ours(d: &dyn Docker) -> Result<Option<bool>, DevError> {
    let args = [
        "network",
        "inspect",
        NETWORK,
        "--format",
        "{{json .Labels}}",
    ];
    let out = d.run(&args, None)?;
    if out.status != 0 {
        let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if err.contains("not found") || err.contains("no such network") {
            return Ok(None);
        }
        return Err(docker_error(&args, out));
    }
    let labels: Option<BTreeMap<String, String>> =
        serde_json::from_slice(&out.stdout).unwrap_or(None);
    let labels = labels.unwrap_or_default();
    Ok(Some(
        labels.get(MANAGED).map(String::as_str) == Some("true")
            && labels.get(ROLE).map(String::as_str) == Some("network"),
    ))
}

/// Creates the shared `saiife-dev` network if it is missing; refuses one
/// saiife did not create.
pub fn ensure_network(d: &dyn Docker) -> Result<(), DevError> {
    let not_ours = || DevError::NotOurs {
        kind: "network",
        name: NETWORK.into(),
    };
    match network_is_ours(d)? {
        Some(true) => return Ok(()),
        Some(false) => return Err(not_ours()),
        None => {}
    }
    let managed = format!("{MANAGED}=true");
    let role = format!("{ROLE}=network");
    let created = run_ok(
        d,
        &[
            "network", "create", "--driver", "bridge", "--label", &managed, "--label", &role,
            NETWORK,
        ],
    );
    match created {
        Ok(_) => Ok(()),
        // Another `up` may have created it first.
        Err(e) => match network_is_ours(d) {
            Ok(Some(true)) => Ok(()),
            Ok(Some(false)) => Err(not_ours()),
            _ => Err(e),
        },
    }
}

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
    use crate::docker::{FakeDocker, Output};
    use std::fs;
    use std::net::TcpListener;
    use std::sync::Mutex;

    // plan 23 task 4
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn probe_sees_a_held_port() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        assert_eq!(probe_bind(l.local_addr().unwrap().port()), Probe::InUse);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn skip_env_makes_probe_unknown() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        std::env::set_var("SAIIFE_DEV_SKIP_PORT_BIND", "1");
        let got = probe_bind(l.local_addr().unwrap().port());
        std::env::remove_var("SAIIFE_DEV_SKIP_PORT_BIND");
        assert_eq!(got, Probe::Unknown);
    }

    const PS_PROXY: &[&str] = &[
        "ps",
        "--filter",
        "label=saiife.managed=true",
        "--filter",
        "label=saiife.dev.role=proxy",
        "--format",
        "{{.Names}}",
    ];

    #[test]
    fn running_proxy_passes() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok("saiife-dev-proxy\n"));
        preflight_ports_with(&d, &|_| panic!("probe must not run")).unwrap();
    }

    #[test]
    fn similar_name_is_not_the_proxy() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok("saiife-dev-proxy-old\n"));
        let called = std::cell::Cell::new(false);
        preflight_ports_with(&d, &|_| {
            called.set(true);
            Probe::Free
        })
        .unwrap();
        assert!(called.get());
    }

    #[test]
    fn free_ports_pass() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok(""));
        preflight_ports_with(&d, &|_| Probe::Free).unwrap();
    }

    #[test]
    fn busy_port_names_the_container() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok(""));
        d.on(&["ps", "--filter", "publish=443"], Output::ok("web-1\n"));
        let e = preflight_ports_with(&d, &|p| {
            if p == 443 {
                Probe::InUse
            } else {
                Probe::Free
            }
        })
        .unwrap_err();
        assert!(matches!(
            &e,
            DevError::PortBusy { port: 443, holder: Some(h) } if h == "web-1"
        ));
        assert_eq!(
            e.to_string(),
            "port 443 on 127.0.0.1 is in use by container web-1; stop it, then run saiife dev up again"
        );
    }

    #[test]
    fn in_use_with_no_container_says_another_program() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok(""));
        d.on(&["ps", "--filter", "publish="], Output::ok(""));
        let e = preflight_ports_with(&d, &|_| Probe::InUse).unwrap_err();
        assert!(matches!(
            e,
            DevError::PortBusy {
                port: 80,
                holder: None
            }
        ));
        assert!(e.to_string().contains("in use by another program; stop it"));
    }

    #[test]
    fn unknown_port_with_no_container_passes() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok(""));
        d.on(&["ps", "--filter", "publish="], Output::ok(""));
        preflight_ports_with(&d, &|_| Probe::Unknown).unwrap();
    }

    #[test]
    fn unknown_port_with_container_is_busy() {
        let d = FakeDocker::new();
        d.on(PS_PROXY, Output::ok(""));
        d.on(&["ps", "--filter", "publish=80"], Output::ok("nginx\n"));
        let e = preflight_ports_with(&d, &|_| Probe::Unknown).unwrap_err();
        assert!(matches!(
            &e,
            DevError::PortBusy { port: 80, holder: Some(h) } if h == "nginx"
        ));
    }

    const INSPECT: &[&str] = &[
        "network",
        "inspect",
        "saiife-dev",
        "--format",
        "{{json .Labels}}",
    ];
    const CREATE: &[&str] = &[
        "network",
        "create",
        "--driver",
        "bridge",
        "--label",
        "saiife.managed=true",
        "--label",
        "saiife.dev.role=network",
        "saiife-dev",
    ];
    const OURS: &str = r#"{"saiife.managed":"true","saiife.dev.role":"network"}"#;

    fn created(d: &FakeDocker) -> usize {
        d.calls()
            .iter()
            .filter(|c| c.args.iter().map(String::as_str).eq(CREATE.iter().copied()))
            .count()
    }

    #[test]
    fn network_is_created_when_missing() {
        let d = FakeDocker::new();
        d.on(
            INSPECT,
            Output::fail(1, "Error: network saiife-dev not found"),
        );
        d.on(CREATE, Output::ok("abc\n"));
        ensure_network(&d).unwrap();
        assert_eq!(created(&d), 1);
    }

    #[test]
    fn existing_network_is_kept() {
        let d = FakeDocker::new();
        d.on(INSPECT, Output::ok(OURS));
        ensure_network(&d).unwrap();
        assert_eq!(created(&d), 0);
    }

    #[test]
    fn foreign_network_is_refused() {
        let d = FakeDocker::new();
        d.on(INSPECT, Output::ok("{}"));
        let e = ensure_network(&d).unwrap_err();
        assert!(matches!(
            &e,
            DevError::NotOurs { kind: "network", name } if name == "saiife-dev"
        ));
        assert_eq!(created(&d), 0);
    }

    #[test]
    fn create_race_is_tolerated() {
        let d = FakeDocker::new();
        d.once(INSPECT, Output::fail(1, "network saiife-dev not found"));
        d.on(INSPECT, Output::ok(OURS));
        d.on(
            CREATE,
            Output::fail(1, "network with name saiife-dev already exists"),
        );
        ensure_network(&d).unwrap();
    }

    #[test]
    fn docker_down_is_an_error() {
        let d = FakeDocker::new();
        d.on(
            INSPECT,
            Output::fail(1, "Cannot connect to the Docker daemon"),
        );
        assert!(matches!(
            ensure_network(&d).unwrap_err(),
            DevError::Docker { .. }
        ));
        assert_eq!(created(&d), 0);
        // The error comes from the first inspect; it is not run again.
        assert_eq!(d.calls().len(), 1);
    }

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

// plan 23 task 5: the proxy container.

/// The Traefik image. The owner appends `@sha256:<digest>`.
pub const PROXY_IMAGE: &str = "traefik:v3.7.16";

/// Label carrying `spec_hash(run_args)`; a different value means recreate.
const SPEC: &str = "saiife.dev.proxy-spec";

/// `--user <uid>:<gid>` of the owner of `paths.state` (or of its nearest
/// existing ancestor, before the first `up` creates it), so the proxy can read
/// the user's 0600 leaf keys.
#[cfg(unix)]
fn user_arg(paths: &DevPaths) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = paths.state.ancestors().find_map(|p| fs::metadata(p).ok())?;
    Some(format!("{}:{}", meta.uid(), meta.gid()))
}

/// The full `docker run` argument list for the proxy, without the spec label.
pub(crate) fn run_args(paths: &DevPaths) -> Vec<String> {
    let dynamic = format!("{}:/saiife/dynamic:ro", dynamic_dir(paths).display());
    let tls = format!("{}:/saiife/tls:ro", tls_dir(paths).display());
    let managed = format!("{MANAGED}=true");
    let role = format!("{ROLE}=proxy");
    let mut a: Vec<String> = [
        "run",
        "-d",
        "--name",
        PROXY_CONTAINER,
        "--network",
        NETWORK,
        "--restart",
        "unless-stopped",
        "--label",
        &managed,
        "--label",
        &role,
        "-p",
        "127.0.0.1:80:8080",
        "-p",
        "127.0.0.1:443:8443",
        "-v",
        &dynamic,
        "-v",
        &tls,
        "--read-only",
        "--tmpfs",
        "/tmp",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    #[cfg(unix)]
    if let Some(user) = user_arg(paths) {
        a.push("--user".into());
        a.push(user);
    }
    a.push(PROXY_IMAGE.into());
    a.extend(
        [
            "--providers.file.directory=/saiife/dynamic",
            "--providers.file.watch=true",
            "--entryPoints.web.address=:8080",
            "--entryPoints.web.http.redirections.entryPoint.to=:443",
            "--entryPoints.web.http.redirections.entryPoint.scheme=https",
            "--entryPoints.web.http.redirections.entryPoint.permanent=true",
            "--entryPoints.websecure.address=:8443",
            "--global.checkNewVersion=false",
            "--global.sendAnonymousUsage=false",
            "--log.level=INFO",
        ]
        .map(String::from),
    );
    a
}

/// FNV-1a 64-bit over the arguments joined with `\0`, as 16 lowercase hex
/// digits. Drift detection only; not security-relevant.
pub(crate) fn spec_hash(args: &[String]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, a) in args.iter().enumerate() {
        let sep: &[u8] = if i == 0 { b"" } else { b"\0" };
        for &b in sep.iter().chain(a.as_bytes()) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// What `container inspect saiife-dev-proxy` said.
struct Inspected {
    labels: BTreeMap<String, String>,
    running: bool,
}

impl Inspected {
    fn ours(&self) -> bool {
        self.labels.get(MANAGED).map(String::as_str) == Some("true")
            && self.labels.get(ROLE).map(String::as_str) == Some("proxy")
    }
}

/// `None` when no container has the proxy's name.
fn inspect_proxy(d: &dyn Docker) -> Result<Option<Inspected>, DevError> {
    let args = ["container", "inspect", PROXY_CONTAINER];
    let out = d.run(&args, None)?;
    if out.status != 0 {
        let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
        if err.contains("no such container") || err.contains("no such object") {
            return Ok(None);
        }
        return Err(docker_error(&args, out));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let first = &v[0];
    let labels = first["Config"]["Labels"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Inspected {
        labels,
        running: first["State"]["Running"].as_bool().unwrap_or(false),
    }))
}

fn remove_proxy(d: &dyn Docker) -> Result<(), DevError> {
    run_ok(d, &["rm", "-f", PROXY_CONTAINER]).map(|_| ())
}

/// Runs `run` or `start`; on failure removes the container and maps an
/// address-in-use error to `PortBusy`.
///
/// After a failed `run` the container is removed only when a fresh inspect
/// shows it is ours, and never on a name conflict: that container belongs to a
/// concurrent `up` (or to someone else). A failed `start` is of a container
/// already inspected as ours.
fn run_or_clean(d: &dyn Docker, args: &[&str]) -> Result<(), DevError> {
    let e = match run_ok(d, args) {
        Ok(_) => return Ok(()),
        Err(e) => e,
    };
    let conflict = matches!(&e, DevError::Docker { stderr, .. }
        if stderr.contains("is already in use by container"));
    let clean = if args.first() == Some(&"run") {
        !conflict && matches!(inspect_proxy(d), Ok(Some(c)) if c.ours())
    } else {
        true
    };
    if clean {
        // Best effort: the next `up` must start clean; the run error is the one to report.
        let _ = remove_proxy(d);
    }
    match e {
        DevError::Docker { ref stderr, .. }
            if stderr.contains("address already in use")
                || stderr.contains("port is already allocated") =>
        {
            Err(DevError::PortBusy {
                port: if stderr.contains(":443") { 443 } else { 80 },
                holder: None,
            })
        }
        e => Err(e),
    }
}

fn mkdir(dir: PathBuf) -> Result<(), DevError> {
    fs::create_dir_all(&dir).map_err(|source| DevError::Io { path: dir, source })
}

/// Makes sure the one `saiife-dev-proxy` container runs with today's spec.
/// Refuses a container of that name that saiife did not create.
pub fn ensure_proxy(d: &dyn Docker, paths: &DevPaths) -> Result<(), DevError> {
    // D1: if these were missing, Docker would create them owned by root.
    mkdir(dynamic_dir(paths))?;
    mkdir(tls_dir(paths))?;
    let mut args = run_args(paths);
    let spec = spec_hash(&args);
    let at = args
        .iter()
        .position(|a| *a == format!("{ROLE}=proxy"))
        .map_or(args.len(), |i| i + 1);
    args.splice(at..at, ["--label".into(), format!("{SPEC}={spec}")]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match inspect_proxy(d)? {
        None => run_or_clean(d, &args),
        Some(c) if !c.ours() => Err(DevError::NotOurs {
            kind: "container",
            name: PROXY_CONTAINER.into(),
        }),
        Some(c) if c.labels.get(SPEC) != Some(&spec) => {
            remove_proxy(d)?;
            run_or_clean(d, &args)
        }
        Some(c) if !c.running => run_or_clean(d, &["start", PROXY_CONTAINER]),
        Some(_) => Ok(()),
    }
}

/// Whether any project route file is left in the dynamic directory.
fn routes_left(paths: &DevPaths) -> Result<bool, DevError> {
    let dir = dynamic_dir(paths);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(DevError::Io { path: dir, source }),
    };
    for entry in entries {
        let entry = entry.map_err(|source| DevError::Io {
            path: dir.clone(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".toml") && name != TLS_FILE {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Removes the proxy once no project has routes left. Returns `true` when it
/// removed the proxy. A missing or foreign container is left alone.
pub fn stop_proxy_if_unused(d: &dyn Docker, paths: &DevPaths) -> Result<bool, DevError> {
    if routes_left(paths)? {
        return Ok(false);
    }
    match inspect_proxy(d)? {
        Some(c) if c.ours() => remove_proxy(d).map(|()| true),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod container_tests {
    use super::*;

    use crate::docker::{FakeDocker, Output};

    const INSPECT: &[&str] = &["container", "inspect", "saiife-dev-proxy"];
    const RM: &[&str] = &["rm", "-f", "saiife-dev-proxy"];
    const START: &[&str] = &["start", "saiife-dev-proxy"];
    const MISSING: &str = "Error: No such container: saiife-dev-proxy";

    fn setup() -> (tempfile::TempDir, DevPaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = DevPaths {
            state: d.path().join("state"),
            config: d.path().join("config"),
        };
        (d, paths)
    }

    fn full_args(paths: &DevPaths) -> Vec<String> {
        let mut a = run_args(paths);
        let h = spec_hash(&a);
        let at = a.iter().position(|x| x == "saiife.dev.role=proxy").unwrap() + 1;
        a.insert(at, "--label".into());
        a.insert(at + 1, format!("saiife.dev.proxy-spec={h}"));
        a
    }

    fn inspect_reply(labels: &str, running: bool) -> Output {
        Output::ok(format!(
            r#"[{{"Config":{{"Labels":{labels}}},"State":{{"Running":{running}}}}}]"#
        ))
    }

    fn ours(paths: &DevPaths, spec: Option<&str>) -> String {
        let spec = spec.map_or_else(|| spec_hash(&run_args(paths)), str::to_string);
        format!(
            r#"{{"saiife.managed":"true","saiife.dev.role":"proxy","saiife.dev.proxy-spec":"{spec}"}}"#
        )
    }

    fn count(d: &FakeDocker, prefix: &[&str]) -> usize {
        d.calls()
            .iter()
            .filter(|c| {
                c.args.len() >= prefix.len() && c.args.iter().zip(prefix).all(|(a, p)| a == p)
            })
            .count()
    }

    fn has_pair(a: &[String], x: &str, y: &str) -> bool {
        a.windows(2).any(|w| w[0] == x && w[1] == y)
    }

    #[test]
    fn run_args_are_locked_down() {
        // A state path outside any `/projects` directory, so the check below
        // sees only what saiife itself adds.
        let paths = DevPaths {
            state: PathBuf::from("/nonexistent-p23/state"),
            config: PathBuf::from("/nonexistent-p23/config"),
        };
        let a = run_args(&paths);
        assert_eq!(&a[..2], &["run", "-d"]);
        assert!(a.iter().any(|x| x == "--read-only"));
        assert!(has_pair(&a, "--cap-drop", "ALL"));
        assert!(has_pair(&a, "-p", "127.0.0.1:80:8080"));
        assert!(has_pair(&a, "-p", "127.0.0.1:443:8443"));
        let dynamic = format!("{}:/saiife/dynamic:ro", dynamic_dir(&paths).display());
        let tls = format!("{}:/saiife/tls:ro", tls_dir(&paths).display());
        assert!(has_pair(&a, "-v", &dynamic), "{a:?}");
        assert!(has_pair(&a, "-v", &tls), "{a:?}");
        assert_eq!(a.iter().filter(|x| *x == "-v").count(), 2);
        assert!(a
            .iter()
            .any(|x| x == "--providers.file.directory=/saiife/dynamic"));
        assert!(a
            .iter()
            .any(|x| x == "--entryPoints.web.http.redirections.entryPoint.to=:443"));
        let ca = paths.ca_dir().display().to_string();
        for x in &a {
            assert!(!x.contains("docker.sock"), "{x}");
            assert!(!x.contains("providers.docker"), "{x}");
            assert!(!x.contains("/projects"), "{x}");
            assert!(!x.contains(&ca), "{x}");
        }
        let img = a.iter().position(|x| x == PROXY_IMAGE).unwrap();
        assert_eq!(
            &a[img + 1..],
            &[
                "--providers.file.directory=/saiife/dynamic",
                "--providers.file.watch=true",
                "--entryPoints.web.address=:8080",
                "--entryPoints.web.http.redirections.entryPoint.to=:443",
                "--entryPoints.web.http.redirections.entryPoint.scheme=https",
                "--entryPoints.web.http.redirections.entryPoint.permanent=true",
                "--entryPoints.websecure.address=:8443",
                "--global.checkNewVersion=false",
                "--global.sendAnonymousUsage=false",
                "--log.level=INFO",
            ]
        );
        assert_eq!(a.iter().any(|x| x == "--user"), cfg!(unix));
    }

    #[test]
    fn image_is_pinned() {
        let rest = PROXY_IMAGE.strip_prefix("traefik:v3.7.16").unwrap();
        if !rest.is_empty() {
            let hex = rest.strip_prefix("@sha256:").unwrap();
            assert_eq!(hex.len(), 64);
            assert!(hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }

    #[test]
    fn missing_proxy_is_run() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, Output::fail(1, MISSING));
        d.on(&["run"], Output::ok("id\n"));
        ensure_proxy(&d, &paths).unwrap();
        assert!(dynamic_dir(&paths).is_dir());
        assert!(tls_dir(&paths).is_dir());
        let runs: Vec<_> = d
            .calls()
            .into_iter()
            .filter(|c| c.args[0] == "run")
            .collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].args, full_args(&paths));
        assert_eq!(count(&d, RM), 0);
    }

    #[test]
    fn running_proxy_with_same_spec_is_left_alone() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), true));
        ensure_proxy(&d, &paths).unwrap();
        assert_eq!(
            count(&d, &["run"]) + count(&d, &["start"]) + count(&d, &["rm"]),
            0
        );
    }

    #[test]
    fn stopped_proxy_is_started() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), false));
        d.on(START, Output::ok("saiife-dev-proxy\n"));
        ensure_proxy(&d, &paths).unwrap();
        assert_eq!(count(&d, START), 1);
        assert_eq!(count(&d, &["run"]) + count(&d, &["rm"]), 0);
    }

    #[test]
    fn changed_spec_is_recreated() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(
            INSPECT,
            inspect_reply(&ours(&paths, Some("0000000000000000")), true),
        );
        d.on(RM, Output::ok("saiife-dev-proxy\n"));
        d.on(&["run"], Output::ok("id\n"));
        ensure_proxy(&d, &paths).unwrap();
        let tail: Vec<_> = d.calls().into_iter().skip(1).map(|c| c.args).collect();
        assert_eq!(tail.len(), 2, "{tail:?}");
        assert_eq!(tail[0], RM);
        assert_eq!(tail[1], full_args(&paths));
    }

    #[test]
    fn foreign_container_is_refused() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply("null", true));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(matches!(
            &e,
            DevError::NotOurs { kind: "container", name } if name == "saiife-dev-proxy"
        ));
        assert_eq!(count(&d, &["rm"]) + count(&d, &["run"]), 0);
    }

    #[test]
    fn failed_run_removes_the_container() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.once(INSPECT, Output::fail(1, MISSING));
        // The half-made container `run` left behind carries our labels.
        d.on(INSPECT, inspect_reply(&ours(&paths, None), false));
        d.on(
            &["run"],
            Output::fail(
                125,
                "Bind for 127.0.0.1:443 failed: port is already allocated",
            ),
        );
        d.on(RM, Output::ok("saiife-dev-proxy\n"));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(
            matches!(
                e,
                DevError::PortBusy {
                    port: 443,
                    holder: None
                }
            ),
            "{e:?}"
        );
        assert_eq!(d.calls().last().unwrap().args, RM);
    }

    #[test]
    fn failed_start_on_80_is_port_busy() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), false));
        d.on(
            START,
            Output::fail(1, "listen tcp4 127.0.0.1:80: bind: address already in use"),
        );
        d.on(RM, Output::ok(""));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(
            matches!(
                e,
                DevError::PortBusy {
                    port: 80,
                    holder: None
                }
            ),
            "{e:?}"
        );
        assert_eq!(d.calls().last().unwrap().args, RM);
    }

    #[test]
    fn other_run_failure_is_a_docker_error() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, Output::fail(1, MISSING));
        d.on(&["run"], Output::fail(125, "Unable to find image"));
        d.on(RM, Output::ok(""));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(matches!(e, DevError::Docker { status: 125, .. }), "{e:?}");
        // Nothing was created, so the re-inspect finds nothing to remove.
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn run_conflict_removes_nothing() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.once(INSPECT, Output::fail(1, MISSING));
        // A concurrent `up` won the race; its proxy is ours but not this run's.
        d.on(INSPECT, inspect_reply(&ours(&paths, None), true));
        d.on(
            &["run"],
            Output::fail(
                125,
                "docker: Error response from daemon: Conflict. The container name \
                 \"/saiife-dev-proxy\" is already in use by container \"abc\".",
            ),
        );
        d.on(RM, Output::ok(""));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(matches!(e, DevError::Docker { status: 125, .. }), "{e:?}");
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn failed_run_keeps_a_foreign_container() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.once(INSPECT, Output::fail(1, MISSING));
        d.on(INSPECT, inspect_reply(r#"{"maintainer":"someone"}"#, true));
        d.on(
            &["run"],
            Output::fail(
                125,
                "Bind for 127.0.0.1:443 failed: port is already allocated",
            ),
        );
        d.on(RM, Output::ok(""));
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(matches!(e, DevError::PortBusy { port: 443, .. }), "{e:?}");
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn failed_inspect_is_not_rerun() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(
            INSPECT,
            Output::fail(1, "  Cannot connect to the Docker daemon\n"),
        );
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(
            matches!(&e, DevError::Docker { status: 1, stderr, args }
                if stderr == "Cannot connect to the Docker daemon" && args[1] == "inspect"),
            "{e:?}"
        );
        assert_eq!(d.calls().len(), 1);
    }

    #[test]
    fn docker_down_is_an_error() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(
            INSPECT,
            Output::fail(1, "Cannot connect to the Docker daemon"),
        );
        let e = ensure_proxy(&d, &paths).unwrap_err();
        assert!(matches!(e, DevError::Docker { .. }), "{e:?}");
        assert_eq!(count(&d, &["run"]) + count(&d, &["rm"]), 0);
    }

    fn touch(paths: &DevPaths, name: &str) {
        let dir = dynamic_dir(paths);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), "").unwrap();
    }

    #[test]
    fn proxy_kept_while_routes_exist() {
        let (_t, paths) = setup();
        touch(&paths, "shop.toml");
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), true));
        assert!(!stop_proxy_if_unused(&d, &paths).unwrap());
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn tls_file_alone_does_not_keep_the_proxy() {
        let (_t, paths) = setup();
        touch(&paths, TLS_FILE);
        touch(&paths, ".shop.toml.tmp");
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), true));
        d.on(RM, Output::ok(""));
        assert!(stop_proxy_if_unused(&d, &paths).unwrap());
        assert_eq!(d.calls().last().unwrap().args, RM);
    }

    #[test]
    fn unused_proxy_is_removed() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(&ours(&paths, None), false));
        d.on(RM, Output::ok(""));
        assert!(stop_proxy_if_unused(&d, &paths).unwrap());
        assert_eq!(count(&d, RM), 1);
    }

    #[test]
    fn missing_proxy_is_not_removed() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, Output::fail(1, MISSING));
        assert!(!stop_proxy_if_unused(&d, &paths).unwrap());
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn foreign_proxy_is_not_removed() {
        let (_t, paths) = setup();
        let d = FakeDocker::new();
        d.on(INSPECT, inspect_reply(r#"{"maintainer":"someone"}"#, true));
        assert!(!stop_proxy_if_unused(&d, &paths).unwrap());
        assert_eq!(count(&d, &["rm"]), 0);
    }

    #[test]
    fn spec_hash_is_stable() {
        // Published FNV-1a 64 vectors.
        assert_eq!(spec_hash(&[]), "cbf29ce484222325");
        assert_eq!(spec_hash(&["a".into()]), "af63dc4c8601ec8c");
        assert_eq!(spec_hash(&["foobar".into()]), "85944171f73967e8");
        let a: Vec<String> = ["run", "-d", "x"].map(String::from).to_vec();
        let mut b = a.clone();
        b[2] = "y".into();
        assert_eq!(spec_hash(&a).len(), 16);
        assert_ne!(spec_hash(&a), spec_hash(&b));
        // The separator counts: ["ab"] is not ["a", "b"].
        assert_ne!(
            spec_hash(&["ab".into()]),
            spec_hash(&["a".into(), "b".into()])
        );
    }
}
