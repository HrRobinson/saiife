//! Rewriting the compose model for `saiife dev up`.
use crate::compose::{ComposeModel, ServiceInfo};
use crate::labels::{compose_project, label_map, NETWORK};
use crate::project::{check_name, dns_label};
use crate::quirks::Quirks;
use crate::DevError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Top-level resource kinds whose default names carry the compose project.
const RESOURCES: [&str; 4] = ["networks", "volumes", "configs", "secrets"];

/// One routed service, decided before the model changes.
struct Plan<'a> {
    service: &'a str,
    label: String,
    port: u16,
    scheme: String,
}

fn bad(msg: impl Into<String>) -> DevError {
    DevError::Rewrite(msg.into())
}

/// `labels` as an object: a `["k=v"]` list is turned into one.
fn labels_object(v: Option<&Value>, what: &str) -> Result<Map<String, Value>, DevError> {
    match v {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(o)) => Ok(o.clone()),
        Some(Value::Array(a)) => {
            let mut o = Map::new();
            for e in a {
                let s = e
                    .as_str()
                    .ok_or_else(|| bad(format!("{what}: a labels entry is not a string")))?;
                let (k, val) = s.split_once('=').unwrap_or((s, ""));
                o.insert(k.to_string(), Value::from(val));
            }
            Ok(o)
        }
        Some(_) => Err(bad(format!("{what}: labels is not an object or a list"))),
    }
}

/// Merges saiife's labels into `obj["labels"]`; saiife's keys win.
fn add_labels(
    obj: &mut Map<String, Value>,
    ours: &BTreeMap<String, String>,
    what: &str,
) -> Result<(), DevError> {
    let mut l = labels_object(obj.get("labels"), what)?;
    for (k, v) in ours {
        l.insert(k.clone(), Value::from(v.as_str()));
    }
    obj.insert("labels".into(), Value::Object(l));
    Ok(())
}

/// The port a service is routed to: quirk, first TCP `ports` target, first `expose`.
fn port_for(info: &ServiceInfo, quirk: Option<u16>) -> Option<u16> {
    quirk
        .or_else(|| {
            info.ports
                .iter()
                .find(|p| p.protocol == "tcp")
                .map(|p| p.target)
        })
        .or_else(|| info.expose.first().copied())
}

/// Picks the routed services (D5) and checks their labels do not clash.
fn plan_routes<'a>(
    m: &'a ComposeModel,
    services: &Map<String, Value>,
    q: &Quirks,
) -> Result<Vec<Plan<'a>>, DevError> {
    let mut plans = Vec::new();
    let mut taken: BTreeMap<String, &str> = BTreeMap::new();
    for info in &m.services {
        let quirk = q.services.get(&info.name);
        if quirk.is_some_and(|s| s.skip) {
            continue;
        }
        let def = services.get(&info.name).and_then(Value::as_object);
        if def.is_some_and(|d| d.contains_key("network_mode")) {
            continue;
        }
        let Some(port) = port_for(info, quirk.and_then(|s| s.port)) else {
            continue;
        };
        let label = match quirk.and_then(|s| s.host.clone()) {
            Some(h) => h,
            None => dns_label(&info.name).ok_or_else(|| {
                bad(format!(
                    "service {}: its name has no letters or digits to use as a host name; set host in its quirk",
                    info.name
                ))
            })?,
        };
        if let Some(other) = taken.insert(label.clone(), &info.name) {
            return Err(bad(format!(
                "services {other} and {} both want the host name {label}; set host in a quirk for one of them",
                info.name
            )));
        }
        let scheme = quirk
            .and_then(|s| s.scheme.clone())
            .unwrap_or_else(|| "http".into());
        plans.push(Plan {
            service: &info.name,
            label,
            port,
            scheme,
        });
    }
    Ok(plans)
}

/// One proxy route: `host` is served by `upstream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub host: String,
    pub upstream: String,
    pub upstream_scheme: String,
    pub service: String,
}

/// The model `saiife dev up` starts, and the routes for the proxy.
#[derive(Debug, Clone)]
pub struct Rewritten {
    pub model: serde_json::Value,
    /// Sorted by service.
    pub routes: Vec<Route>,
}

/// Rewrites a compose model for a saiife dev project. Writes no file.
pub fn rewrite(m: &ComposeModel, project: &str, q: &Quirks) -> Result<Rewritten, DevError> {
    check_name(project)?;
    let mut raw = m.raw.clone();
    let top = raw
        .as_object_mut()
        .ok_or_else(|| DevError::ComposeJson("not a JSON object".into()))?;
    let orig = top
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| DevError::ComposeJson("the model has no name".into()))?
        .to_string();
    let cp = compose_project(project);
    let ours = label_map(project);

    if top
        .get("networks")
        .and_then(Value::as_object)
        .is_some_and(|n| n.contains_key(NETWORK))
    {
        return Err(bad(format!(
            "the network name {NETWORK} is reserved for saiife"
        )));
    }

    let mut services = match top.remove("services") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(s)) => s,
        Some(_) => return Err(DevError::ComposeJson("services is not an object".into())),
    };
    let plans = plan_routes(m, &services, q)?;

    // 2. The compose project name.
    top.insert("name".into(), Value::from(cp.as_str()));

    // 3 and 4. No host ports; saiife's labels on every service.
    for (name, def) in services.iter_mut() {
        let def = def
            .as_object_mut()
            .ok_or_else(|| bad(format!("service {name} is not an object")))?;
        def.remove("ports");
        add_labels(def, &ours, &format!("service {name}"))?;
    }

    // 5. Rename and label the resources compose named after the original project.
    for kind in RESOURCES {
        let Some(Value::Object(entries)) = top.get_mut(kind) else {
            continue;
        };
        for (key, entry) in entries.iter_mut() {
            let Some(e) = entry.as_object_mut() else {
                continue;
            };
            if matches!(
                e.get("external"),
                Some(Value::Bool(true) | Value::Object(_))
            ) {
                continue;
            }
            if e.get("name").and_then(Value::as_str) != Some(&format!("{orig}_{key}")) {
                continue;
            }
            e.insert("name".into(), Value::from(format!("{cp}_{key}")));
            add_labels(e, &ours, &format!("{kind}.{key}"))?;
        }
    }

    // 6. Routed services join the shared network with their alias.
    let mut routes = Vec::new();
    let mut uses_default = false;
    for p in &plans {
        let alias = format!("{}.{project}", p.label);
        let Some(Value::Object(def)) = services.get_mut(p.service) else {
            return Err(bad(format!("service {} is not an object", p.service)));
        };
        let nets = def.entry("networks").or_insert(Value::Null);
        if nets.is_null() {
            uses_default = true;
            *nets = serde_json::json!({ "default": null });
        }
        let nets = nets
            .as_object_mut()
            .ok_or_else(|| bad(format!("service {}: networks is not an object", p.service)))?;
        nets.insert(NETWORK.into(), serde_json::json!({ "aliases": [alias] }));
        routes.push(Route {
            host: format!("{alias}.localhost"),
            upstream: format!("{}://{alias}:{}", p.scheme, p.port),
            upstream_scheme: p.scheme.clone(),
            service: p.service.to_string(),
        });
    }
    top.insert("services".into(), Value::Object(services));

    // 7. The shared network itself, and `default` if a service now needs it.
    if !plans.is_empty() {
        let nets = top.entry("networks").or_insert(Value::Null);
        if nets.is_null() {
            *nets = Value::Object(Map::new());
        }
        let nets = nets
            .as_object_mut()
            .ok_or_else(|| DevError::ComposeJson("networks is not an object".into()))?;
        if uses_default && !nets.contains_key("default") {
            let mut d = Map::new();
            d.insert("name".into(), Value::from(format!("{cp}_default")));
            add_labels(&mut d, &ours, "networks.default")?;
            nets.insert("default".into(), Value::Object(d));
        }
        nets.insert(
            NETWORK.into(),
            serde_json::json!({ "name": NETWORK, "external": true }),
        );
    }

    routes.sort_by(|a, b| a.service.cmp(&b.service));
    Ok(Rewritten { model: raw, routes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::parse_model;
    use crate::quirks::ServiceQuirk;
    use serde_json::{json, Value};

    const V2: &[u8] = include_bytes!("../tests/fixtures/config-v2.json");

    fn model(v: Value) -> ComposeModel {
        parse_model(v.to_string().as_bytes()).unwrap()
    }

    fn quirks(list: &[(&str, ServiceQuirk)]) -> Quirks {
        Quirks {
            services: list
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    fn rw(v: Value) -> Rewritten {
        rewrite(&model(v), "shop", &Quirks::default()).unwrap()
    }

    fn rewrite_err(v: Value, q: &Quirks) -> String {
        match rewrite(&model(v), "shop", q) {
            Err(DevError::Rewrite(msg)) => msg,
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }

    fn web_on(port: u16) -> Value {
        json!({
            "image": "x",
            "networks": {"default": null},
            "ports": [{"target": port, "published": "8080", "protocol": "tcp"}]
        })
    }

    fn v2() -> Rewritten {
        rewrite(&parse_model(V2).unwrap(), "shop", &Quirks::default()).unwrap()
    }

    #[test]
    fn strips_all_ports() {
        let r = v2();
        for (name, svc) in r.model["services"].as_object().unwrap() {
            assert!(svc.get("ports").is_none(), "{name} kept ports");
        }
    }

    #[test]
    fn sets_project_name() {
        assert_eq!(v2().model["name"], "saiife-shop");
    }

    #[test]
    fn labels_every_service() {
        let r = rw(json!({
            "name": "shop",
            "services": {
                "a": {"image": "x", "labels": {"com.example": "1"}},
                "b": {"image": "x", "labels": ["a=b"]},
                "c": {"image": "x"}
            }
        }));
        for (name, svc) in r.model["services"].as_object().unwrap() {
            assert_eq!(svc["labels"]["saiife.managed"], "true", "{name}");
            assert_eq!(svc["labels"]["saiife.dev.project"], "shop", "{name}");
        }
        assert_eq!(r.model["services"]["a"]["labels"]["com.example"], "1");
        assert_eq!(
            r.model["services"]["b"]["labels"],
            json!({"a": "b", "saiife.managed": "true", "saiife.dev.project": "shop"})
        );
    }

    #[test]
    fn saiife_labels_win() {
        let r = rw(json!({
            "name": "shop",
            "services": {"a": {"image": "x", "labels": {"saiife.dev.project": "other"}}}
        }));
        assert_eq!(
            r.model["services"]["a"]["labels"]["saiife.dev.project"],
            "shop"
        );
    }

    #[test]
    fn renames_default_named_resources() {
        let r = rw(json!({
            "name": "myrepo",
            "services": {"web": web_on(3000)},
            "networks": {"default": {"name": "myrepo_default"}},
            "volumes": {"data": {"name": "myrepo_data"}},
            "configs": {"cfg": {"name": "myrepo_cfg", "file": "/x"}},
            "secrets": {"key": {"name": "myrepo_key", "file": "/y"}}
        }));
        let labels = json!({"saiife.managed": "true", "saiife.dev.project": "shop"});
        assert_eq!(
            r.model["volumes"]["data"],
            json!({"name": "saiife-shop_data", "labels": labels})
        );
        assert_eq!(
            r.model["networks"]["default"],
            json!({"name": "saiife-shop_default", "labels": labels})
        );
        assert_eq!(r.model["configs"]["cfg"]["name"], "saiife-shop_cfg");
        assert_eq!(r.model["configs"]["cfg"]["labels"], labels);
        assert_eq!(r.model["secrets"]["key"]["name"], "saiife-shop_key");
        assert_eq!(r.model["secrets"]["key"]["labels"], labels);
    }

    #[test]
    fn renamed_resource_keeps_user_labels() {
        let r = rw(json!({
            "name": "myrepo",
            "services": {},
            "volumes": {"data": {"name": "myrepo_data", "labels": ["k=v"]}}
        }));
        assert_eq!(r.model["volumes"]["data"]["labels"]["k"], "v");
        assert_eq!(
            r.model["volumes"]["data"]["labels"]["saiife.managed"],
            "true"
        );
    }

    #[test]
    fn custom_and_external_resources_are_not_labelled() {
        let input = json!({
            "name": "myrepo",
            "services": {"web": web_on(3000)},
            "networks": {
                "default": {"name": "myrepo_default"},
                "edge": {"name": "edge", "external": true},
                "ext2": {"name": "myrepo_ext2", "external": true}
            },
            "volumes": {"pg": {"name": "pgdata"}}
        });
        let r = rw(input.clone());
        assert_eq!(r.model["volumes"]["pg"], input["volumes"]["pg"]);
        assert_eq!(r.model["networks"]["edge"], input["networks"]["edge"]);
        assert_eq!(r.model["networks"]["ext2"], input["networks"]["ext2"]);
    }

    #[test]
    fn deprecated_external_object_is_not_labelled() {
        let input = json!({
            "name": "myrepo",
            "services": {"web": web_on(3000)},
            "networks": {"old": {"name": "myrepo_old", "external": {"name": "myrepo_old"}}}
        });
        let r = rw(input.clone());
        assert_eq!(r.model["networks"]["old"], input["networks"]["old"]);
    }

    #[test]
    fn route_from_published_target() {
        let r = v2();
        let web = r.routes.iter().find(|r| r.service == "web").unwrap();
        assert_eq!(
            *web,
            Route {
                host: "web.shop.localhost".into(),
                upstream: "http://web.shop:3000".into(),
                upstream_scheme: "http".into(),
                service: "web".into(),
            }
        );
        assert_eq!(
            r.model["services"]["web"]["networks"],
            json!({"default": null, "saiife-dev": {"aliases": ["web.shop"]}})
        );
    }

    #[test]
    fn route_from_expose() {
        let r = rw(json!({
            "name": "shop",
            "services": {
                "api": {"image": "x", "expose": ["9000"]},
                "worker": {"image": "x"}
            }
        }));
        assert_eq!(r.routes.len(), 1);
        assert_eq!(r.routes[0].upstream, "http://api.shop:9000");
        assert_eq!(
            r.model["services"]["api"]["networks"],
            json!({"default": null, "saiife-dev": {"aliases": ["api.shop"]}})
        );
        assert_eq!(
            r.model["networks"]["default"],
            json!({"name": "saiife-shop_default", "labels": {"saiife.managed": "true", "saiife.dev.project": "shop"}})
        );
        assert!(r.model["services"]["worker"].get("networks").is_none());
    }

    #[test]
    fn udp_only_gets_no_route() {
        let r = rw(json!({
            "name": "shop",
            "services": {"dns": {"image": "x", "ports": [{"target": 53, "published": "53", "protocol": "udp"}]}}
        }));
        assert!(r.routes.is_empty());
        assert!(r.model["services"]["dns"].get("networks").is_none());
    }

    #[test]
    fn quirks_apply() {
        let input = json!({
            "name": "shop",
            "services": {"web": web_on(3000), "worker": {"image": "x", "expose": ["8000"]}}
        });
        let q = quirks(&[
            (
                "web",
                ServiceQuirk {
                    port: Some(4000),
                    scheme: Some("https".into()),
                    host: Some("app".into()),
                    skip: false,
                },
            ),
            (
                "worker",
                ServiceQuirk {
                    skip: true,
                    ..Default::default()
                },
            ),
        ]);
        let r = rewrite(&model(input), "shop", &q).unwrap();
        assert_eq!(
            r.routes,
            vec![Route {
                host: "app.shop.localhost".into(),
                upstream: "https://app.shop:4000".into(),
                upstream_scheme: "https".into(),
                service: "web".into(),
            }]
        );
        assert_eq!(
            r.model["services"]["web"]["networks"]["saiife-dev"],
            json!({"aliases": ["app.shop"]})
        );
        let worker = &r.model["services"]["worker"];
        assert!(worker.get("networks").is_none());
        assert_eq!(worker["labels"]["saiife.managed"], "true");
    }

    #[test]
    fn network_mode_gets_no_route() {
        let r = v2();
        assert!(r.routes.iter().all(|r| r.service != "agent"));
        let agent = &r.model["services"]["agent"];
        assert!(agent.get("networks").is_none());
        assert!(agent.get("ports").is_none());
        let r = rw(json!({
            "name": "shop",
            "services": {"h": {"image": "x", "network_mode": "host", "ports": [{"target": 80, "protocol": "tcp"}]}}
        }));
        assert!(r.routes.is_empty());
        assert!(r.model["services"]["h"].get("networks").is_none());
    }

    #[test]
    fn service_names_become_labels() {
        let r = rw(json!({"name": "shop", "services": {"Web_UI": web_on(3000)}}));
        assert_eq!(r.routes[0].host, "web-ui.shop.localhost");
        assert_eq!(r.routes[0].upstream, "http://web-ui.shop:3000");
        assert_eq!(r.routes[0].service, "Web_UI");
        assert_eq!(
            r.model["services"]["Web_UI"]["networks"]["saiife-dev"],
            json!({"aliases": ["web-ui.shop"]})
        );
    }

    #[test]
    fn label_clash_is_an_error() {
        let msg = rewrite_err(
            json!({"name": "shop", "services": {"web_ui": web_on(1), "web-ui": web_on(2)}}),
            &Quirks::default(),
        );
        assert!(msg.contains("web_ui") && msg.contains("web-ui"), "{msg}");

        let q = quirks(&[(
            "web",
            ServiceQuirk {
                host: Some("api".into()),
                ..Default::default()
            },
        )]);
        let msg = rewrite_err(
            json!({"name": "shop", "services": {"web": web_on(1), "api": web_on(2)}}),
            &q,
        );
        assert!(msg.contains("web") && msg.contains("api"), "{msg}");
    }

    #[test]
    fn skipped_service_does_not_clash() {
        let q = quirks(&[(
            "web-ui",
            ServiceQuirk {
                skip: true,
                ..Default::default()
            },
        )]);
        let r = rewrite(
            &model(json!({"name": "shop", "services": {"web_ui": web_on(1), "web-ui": web_on(2)}})),
            "shop",
            &q,
        )
        .unwrap();
        assert_eq!(r.routes.len(), 1);
        assert_eq!(r.routes[0].service, "web_ui");
    }

    #[test]
    fn shared_network_added_once() {
        let r = v2();
        assert_eq!(
            r.model["networks"]["saiife-dev"],
            json!({"name": "saiife-dev", "external": true})
        );
        let r = rw(json!({"name": "shop", "services": {"w": {"image": "x"}}}));
        let has = r
            .model
            .get("networks")
            .and_then(|n| n.get("saiife-dev"))
            .is_some();
        assert!(!has);
    }

    #[test]
    fn reserved_network_name() {
        let msg = rewrite_err(
            json!({
                "name": "shop",
                "services": {"w": {"image": "x"}},
                "networks": {"saiife-dev": {"name": "mine"}}
            }),
            &Quirks::default(),
        );
        assert!(msg.contains("saiife-dev"), "{msg}");
    }

    #[test]
    fn bad_project_name() {
        let m = parse_model(V2).unwrap();
        assert!(matches!(
            rewrite(&m, "../x", &Quirks::default()),
            Err(DevError::BadProjectName(_))
        ));
    }

    #[test]
    fn missing_name_is_compose_json() {
        let m = model(json!({"services": {}}));
        assert!(matches!(
            rewrite(&m, "shop", &Quirks::default()),
            Err(DevError::ComposeJson(_))
        ));
    }

    #[test]
    fn routes_sorted_and_input_untouched() {
        let m = model(json!({
            "name": "shop",
            "services": {"zed": web_on(1), "alpha": web_on(2), "mid": web_on(3)}
        }));
        let before = m.raw.clone();
        let r = rewrite(&m, "shop", &Quirks::default()).unwrap();
        let names: Vec<_> = r.routes.iter().map(|r| r.service.as_str()).collect();
        assert_eq!(names, ["alpha", "mid", "zed"]);
        assert_eq!(m.raw, before);
    }

    #[test]
    fn dollar_strings_pass_through() {
        let r = rw(json!({
            "name": "shop",
            "services": {"w": {"image": "x", "environment": {"X": "$$HOME"}, "command": "echo $${X}"}}
        }));
        assert_eq!(r.model["services"]["w"]["environment"]["X"], "$$HOME");
        assert_eq!(r.model["services"]["w"]["command"], "echo $${X}");
    }
}
