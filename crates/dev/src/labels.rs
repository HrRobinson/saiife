//! Fixed names and labels shared by every `saiife dev` command.
use std::collections::BTreeMap;

/// Label on every container, network and volume saiife dev owns.
pub const MANAGED: &str = "saiife.managed";
/// Label naming the saiife dev project a resource belongs to.
pub const PROJECT: &str = "saiife.dev.project";
/// The shared network every routed service and the proxy join.
pub const NETWORK: &str = "saiife-dev";
/// The proxy container's name.
pub const PROXY_CONTAINER: &str = "saiife-dev-proxy";

/// The compose project name for a saiife dev project.
pub fn compose_project(p: &str) -> String {
    format!("saiife-{p}")
}

/// The labels a project's resources carry.
pub fn label_map(project: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED.to_string(), "true".to_string()),
        (PROJECT.to_string(), project.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_project_prefixes() {
        assert_eq!(compose_project("shop"), "saiife-shop");
        let m = label_map("shop");
        assert_eq!(m.len(), 2);
        assert_eq!(m["saiife.managed"], "true");
        assert_eq!(m["saiife.dev.project"], "shop");
    }
}
