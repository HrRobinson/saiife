//! The closed access table (spec §9.5). Unknown actions are denied.
//!
//! "Anything that only takes power away is safe remotely."

use crate::source::Template;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Signed,
    Touch,
    MachineOnly,
}

/// One const per remote action name.
pub mod actions {
    pub const APPROVAL_APPROVE: &str = "approval.approve";
    pub const APPROVAL_LIST: &str = "approval.list";
    pub const APPROVAL_REJECT: &str = "approval.reject";
    pub const BOX_DIFF: &str = "box.diff";
    pub const BOX_DISCARD: &str = "box.discard";
    pub const BOX_INBOX: &str = "box.inbox";
    pub const BOX_LAND: &str = "box.land";
    pub const BOX_LIST: &str = "box.list";
    pub const BOX_OVERVIEW: &str = "box.overview";
    pub const BOX_PAUSE: &str = "box.pause";
    pub const BOX_PR: &str = "box.pr";
    pub const BOX_PUSH: &str = "box.push";
    pub const BOX_REORDER: &str = "box.reorder";
    pub const BOX_RESUME: &str = "box.resume";
    pub const BOX_REVISE: &str = "box.revise";
    pub const BOX_SPAWN: &str = "box.spawn";
    pub const BOX_STEER: &str = "box.steer";
    pub const BOX_STOP: &str = "box.stop";
    pub const BOX_TEMPLATES: &str = "box.templates";
    pub const BOX_TERM_READ: &str = "box.term.read";
    pub const LOCKDOWN_ON: &str = "lockdown.on";
    pub const WORKSPACE_TOUCH_BEGIN: &str = "workspace.touch.begin";
    pub const WORKSPACE_WHOAMI: &str = "workspace.whoami";
}

use actions as a;

/// The whole remote table, sorted by name (byte order). `box.spawn` is Signed here and
/// raised to Touch by [`spawn_level`].
pub const REMOTE: &[(&str, Level)] = &[
    (a::APPROVAL_APPROVE, Level::Touch),
    (a::APPROVAL_LIST, Level::Signed),
    (a::APPROVAL_REJECT, Level::Signed),
    (a::BOX_DIFF, Level::Signed),
    (a::BOX_DISCARD, Level::Signed),
    (a::BOX_INBOX, Level::Signed),
    (a::BOX_LAND, Level::Touch),
    (a::BOX_LIST, Level::Signed),
    (a::BOX_OVERVIEW, Level::Signed),
    (a::BOX_PAUSE, Level::Signed),
    (a::BOX_PR, Level::Touch),
    (a::BOX_PUSH, Level::Touch),
    (a::BOX_REORDER, Level::Signed),
    (a::BOX_RESUME, Level::Touch),
    (a::BOX_REVISE, Level::Touch),
    (a::BOX_SPAWN, Level::Signed),
    (a::BOX_STEER, Level::Touch),
    (a::BOX_STOP, Level::Signed),
    (a::BOX_TEMPLATES, Level::Signed),
    (a::BOX_TERM_READ, Level::Signed),
    (a::LOCKDOWN_ON, Level::Signed),
    (a::WORKSPACE_TOUCH_BEGIN, Level::Signed),
    (a::WORKSPACE_WHOAMI, Level::Signed),
];

/// Named so the refusal can say "on the machine". Sorted.
pub const MACHINE_ONLY: &[&str] = &[
    "caps.raise",
    "config.set",
    "connector.add",
    "device.enrol",
    "device.remove",
    "egress.set",
    "lockdown.off",
    "uninstall",
    "vault.add",
    "workspace.confirm",
    "workspace.devices",
    "workspace.pair",
    "workspace.revoke",
    "workspace.sign",
];

/// Hand-kept copy of every `OP_*` value in crates/ipc/src/msg.rs (wire does not depend on
/// ipc). All are MachineOnly unless in [`REMOTE`]; `every_ipc_op_is_classified` keeps it complete.
const IPC_OPS: &[&str] = &[
    "api.call",
    "api.list",
    "api.result",
    "api.token",
    "approval.create",
    "approval.decide",
    "approval.list",
    "approval.show",
    "audit.append",
    "audit.query",
    "audit.rotate_key",
    "box.done",
    "box.gc",
    "cloud.lease",
    "grant.consume",
    "hello",
    "hook.begin",
    "hook.bind",
    "lockdown.set",
    "mcp.call",
    "mcp.list",
    "policy.reload",
    "policy.show",
    "secret.add",
    "secret.lease",
    "secret.list",
    "secret.remove",
    "secret.rotate",
    "status",
    "touch.begin",
    "touch.check",
    "touch.enrol",
    "touch.list",
    "touch.remove",
    // Workspace (plan 29): sorted in with the rest.
    "workspace.devices",
    "workspace.frame",
    "workspace.hello",
    "workspace.pair.begin",
    "workspace.pair.confirm",
    "workspace.pair.finish",
    "workspace.pair.status",
    "workspace.revoke",
    "workspace.sign",
];

/// Exact string match only: no prefixes, wildcards or case folding. `None` means deny.
pub fn level_for(action: &str) -> Option<Level> {
    if let Ok(i) = REMOTE.binary_search_by(|(n, _)| (*n).cmp(action)) {
        return Some(REMOTE[i].1);
    }
    if MACHINE_ONLY.contains(&action) || IPC_OPS.contains(&action) {
        return Some(Level::MachineOnly);
    }
    None
}

/// `box.spawn` needs a touch when the template reaches secrets or the network.
pub fn spawn_level(t: &Template) -> Level {
    if t.has_secrets || t.has_egress {
        Level::Touch
    } else {
        Level::Signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Template;

    #[test]
    fn remote_table_is_sorted_and_unique() {
        for w in REMOTE.windows(2) {
            assert!(w[0].0 < w[1].0, "{} !< {}", w[0].0, w[1].0);
        }
        assert!(MACHINE_ONLY.windows(2).all(|w| w[0] < w[1]));
        let mut ops: Vec<&str> = IPC_OPS.to_vec();
        ops.sort_unstable();
        assert!(ops.windows(2).all(|w| w[0] != w[1]), "duplicate in IPC_OPS");
        for (n, _) in REMOTE {
            assert!(
                !MACHINE_ONLY.contains(n),
                "{n} is in REMOTE and MACHINE_ONLY"
            );
        }
    }

    #[test]
    fn view_and_stop_are_signed() {
        for a in ["box.overview", "box.diff", "box.stop", "lockdown.on"] {
            assert_eq!(level_for(a), Some(Level::Signed), "{a}");
        }
    }

    #[test]
    fn approve_and_push_need_touch() {
        for a in ["box.land", "approval.approve", "box.push", "box.pr"] {
            assert_eq!(level_for(a), Some(Level::Touch), "{a}");
        }
    }

    #[test]
    fn config_policy_devices_are_machine_only() {
        for a in [
            "policy.reload",
            "policy.show",
            "config.set",
            "device.enrol",
            "device.remove",
            "lockdown.off",
            "lockdown.set",
            "secret.add",
            "audit.query",
            "workspace.revoke",
        ] {
            assert_eq!(level_for(a), Some(Level::MachineOnly), "{a}");
        }
    }

    #[test]
    fn near_miss_names_are_unknown() {
        for a in ["", "box", "box.*", "BOX.LIST", "box.list.x", "box.stop "] {
            assert_eq!(level_for(a), None, "{a:?}");
        }
    }

    #[test]
    fn box_done_and_gc_are_machine_only() {
        for a in ["box.done", "box.gc"] {
            assert_eq!(level_for(a), Some(Level::MachineOnly), "{a}");
            assert!(!REMOTE.iter().any(|(n, _)| *n == a), "{a} is remote");
        }
    }

    #[test]
    fn every_ipc_op_is_classified() {
        let src = include_str!("../../ipc/src/msg.rs");
        let mut found = Vec::new();
        for line in src.lines() {
            let line = line.trim_start();
            if !line.starts_with("pub const OP_") {
                continue;
            }
            let Some(i) = line.find(": &str = \"") else {
                continue;
            };
            let rest = &line[i + ": &str = \"".len()..];
            let Some(j) = rest.find('"') else { continue };
            found.push(rest[..j].to_string());
        }
        assert!(found.len() >= 27, "found {}", found.len());
        for v in &found {
            assert!(level_for(v).is_some(), "unclassified ipc op {v}");
            assert!(
                IPC_OPS.contains(&v.as_str()) || REMOTE.iter().any(|(n, _)| n == v),
                "IPC_OPS copy is missing {v}"
            );
        }
    }

    #[test]
    fn signed_actions_are_reads_or_restrictions() {
        const RESTRICTIONS: [&str; 6] = [
            "box.stop",
            "box.pause",
            "box.discard",
            "box.reorder",
            "approval.reject",
            "lockdown.on",
        ];
        const READS: [&str; 9] = [
            "box.overview",
            "box.list",
            "box.diff",
            "box.term.read",
            "box.templates",
            "box.inbox",
            "approval.list",
            "workspace.whoami",
            "workspace.touch.begin",
        ];
        for (name, lvl) in REMOTE {
            if *lvl == Level::Signed && *name != "box.spawn" {
                assert!(
                    RESTRICTIONS.contains(name) || READS.contains(name),
                    "{name} is Signed but neither a read nor a restriction"
                );
            }
        }
    }

    #[test]
    fn spawn_is_raised_by_template() {
        let t = |s, e| Template {
            name: "t".into(),
            description: String::new(),
            has_secrets: s,
            has_egress: e,
        };
        assert_eq!(spawn_level(&t(false, false)), Level::Signed);
        assert_eq!(spawn_level(&t(true, false)), Level::Touch);
        assert_eq!(spawn_level(&t(false, true)), Level::Touch);
        assert_eq!(level_for("box.spawn"), Some(Level::Signed));
    }
}
