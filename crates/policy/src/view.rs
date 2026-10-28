//! What one user may see of the policy (`saiife policy show`): their own
//! scope, the services in it and the guard settings. Nothing about other
//! users' scopes, approvers, notification targets or the vault.

use crate::scope::scope_for;
use crate::system::SystemConfig;
use crate::users::Directory;
use serde_json::{json, Map, Value};

/// `{user, scope: {name, env, projects, services}|null, scope_error?,
/// services: {<name>: <config>}, guard: {packs, ask}}` for `user`. A user
/// in no scope has `scope = null`; one in several has `scope_error`.
pub fn user_view(cfg: &SystemConfig, dir: &dyn Directory, user: &str) -> Value {
    let guard = json!({"packs": cfg.guard.packs, "ask": cfg.guard.ask});
    match scope_for(cfg, dir, user) {
        Ok(Some(s)) => {
            let mut services = Map::new();
            for name in &s.services {
                if let Some(svc) = cfg.services.get(name) {
                    services.insert(name.clone(), serde_json::to_value(svc).unwrap_or_default());
                }
            }
            json!({
                "user": user,
                "scope": {
                    "name": s.name,
                    "env": s.env,
                    "projects": s.projects,
                    "services": s.services,
                },
                "services": services,
                "guard": guard,
            })
        }
        Ok(None) => json!({"user": user, "scope": null, "services": {}, "guard": guard}),
        Err(e) => json!({
            "user": user,
            "scope": null,
            "scope_error": e.to_string(),
            "services": {},
            "guard": guard,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::FixedDirectory;

    fn cfg() -> SystemConfig {
        toml::from_str(
            r#"
version = 2
[[scope]]
name = "a"
users = ["alice"]
services = ["erp"]
env = "prod"
[[scope]]
name = "b"
users = ["bob"]
services = ["crm"]
[services.erp]
connector = "http"
allow = ["invoices:read"]
[services.crm]
connector = "http"
"#,
        )
        .unwrap()
    }

    #[test]
    fn view_holds_only_the_users_own_scope() {
        let d = FixedDirectory::from_text(
            "alice:x:1000:1000::/h:/bin/sh\nbob:x:1001:1001::/h:/bin/sh\n",
            "",
        );
        let v = user_view(&cfg(), &d, "alice");
        assert_eq!(v["scope"]["name"], "a");
        assert!(v["services"].get("erp").is_some());
        assert!(v["services"].get("crm").is_none());
        let text = v.to_string();
        assert!(!text.contains("bob") && !text.contains("\"crm\""), "{text}");
        assert!(user_view(&cfg(), &d, "carol")["scope"].is_null());
    }
}
