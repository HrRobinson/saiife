//! Golden corpus for `cloud.azure` (opt-in — must be enabled explicitly).
//!
//! Precision is the whole point: read verbs (`show`/`list`) and resource NAMES
//! that merely contain "delete" must pass, while genuinely irreversible
//! operations (group/vm/storage-account/aks deletion, role mutations) block.

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.azure".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> (String, String) {
    match e.evaluate(cmd) {
        Decision::Deny { pack, reason, .. } => (pack, reason),
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_azure_commands() {
    let e = engine();
    // (command, substring the reason must contain — proves the class is named)
    let cases = [
        ("az group delete --name prod --yes", "resource group"),
        ("az vm delete --name web --resource-group prod", "virtual machine"),
        (
            "az storage account delete --name acct --resource-group prod",
            "storage account",
        ),
        ("az aks delete --name cluster --resource-group prod", "AKS"),
        // role mutations (privilege / lock-out)
        (
            "az role assignment create --assignee x --role Owner --scope /subscriptions/s",
            "privilege",
        ),
        ("az role assignment delete --assignee x --role Owner", "privilege"),
        ("az role definition delete --name custom-role", "privilege"),
        // global option BEFORE the group must not shift the anchor (separate + attached)
        (
            "az --subscription my-sub group delete --name prod --yes",
            "resource group",
        ),
        ("az --debug vm delete --name web -g prod", "virtual machine"),
        (
            "az --output=json storage account delete --name acct -g prod",
            "storage account",
        ),
        // catch-all long tail
        ("az keyvault delete --name kv", "delete"),
        ("az network vnet delete --name vnet -g prod", "delete"),
        ("az disk delete --name disk -g prod", "delete"),
        ("az --debug sql server delete --name s -g prod", "delete"),
        // sudo-wrapped
        ("sudo az group delete --name prod --yes", "resource group"),
        // chained after a benign command
        ("az account show && az group delete --name prod", "resource group"),
    ];
    for (cmd, needle) in cases {
        let (pack, reason) = deny(&e, cmd);
        assert_eq!(pack, "cloud.azure", "for {cmd:?}");
        assert!(
            reason.contains(needle),
            "reason {reason:?} should mention {needle:?} for {cmd:?}"
        );
    }
}

#[test]
fn allows_safe_azure_commands() {
    let e = engine();
    let allow = [
        // read verbs
        "az group list",
        "az group show --name prod",
        "az vm list",
        "az vm show --name web -g prod",
        "az storage account list",
        "az storage account show --name acct -g prod",
        "az aks list",
        "az aks show --name cluster -g prod",
        "az account show",
        "az account list",
        "az role assignment list --assignee x",
        "az role definition list",
        // "delete" only as a substring of a resource NAME / value
        "az vm show --name delete-me -g prod",
        "az group show -n delete-me",
        "az vm list --query \"[?name=='delete-me']\"",
        // read with a global option in front
        "az --subscription my-sub group list",
        "az --output json vm show --name web -g prod",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
