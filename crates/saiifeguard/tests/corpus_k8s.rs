//! Golden corpus for `container.k8s` (opt-in — must be enabled explicitly).
//!
//! Precision is the whole point: read verbs (`get`/`describe`/`logs`), the
//! reviewed-path verbs (`apply`/`diff`), a single `kubectl delete pod`, and a
//! pod NAMED `pv` must pass, while namespace/pv/pvc deletion, `delete -f`,
//! `--all`, `drain`, and `helm uninstall` must block.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["container.k8s".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_k8s_commands() {
    let e = engine();
    let cases = [
        // namespace deletion (long + short kind, slash form)
        "kubectl delete namespace prod",
        "kubectl delete namespaces prod",
        "kubectl delete ns prod",
        "kubectl delete namespace/prod",
        // persistent volume / claim deletion
        "kubectl delete pv data-vol",
        "kubectl delete persistentvolume data-vol",
        "kubectl delete pvc data-claim",
        "kubectl delete persistentvolumeclaim data-claim",
        "kubectl delete pvc/data-claim",
        // delete from a manifest
        "kubectl delete -f prod.yaml",
        "kubectl delete --filename prod.yaml",
        "kubectl delete -f https://example.com/manifest.yaml",
        // bulk --all delete (flag before and after the kind)
        "kubectl delete pods --all",
        "kubectl delete --all deployments",
        // drain a node
        "kubectl drain node-1",
        "kubectl drain node-1 --ignore-daemonsets --delete-emptydir-data",
        // helm uninstall / legacy delete
        "helm uninstall my-release",
        "helm delete my-release",
        "helm uninstall my-release --namespace prod",
        // global flags before the verb are tolerated
        "kubectl -n prod delete pvc data-claim",
        "kubectl --context prod drain node-1",
        "kubectl --kubeconfig /tmp/kc delete namespace staging",
        "helm --namespace prod uninstall my-release",
        // sudo-wrapped
        "sudo kubectl delete namespace prod",
        // chained after a benign command
        "cd k8s && kubectl delete pv data-vol",
    ];
    for cmd in cases {
        assert_eq!(deny(&e, cmd), "container.k8s", "for {cmd:?}");
    }
}

#[test]
fn allows_safe_k8s_commands() {
    let e = engine();
    let allow = [
        // read verbs
        "kubectl get pods",
        "kubectl get ns",
        "kubectl get pv",
        "kubectl describe pod web",
        "kubectl logs web",
        // reviewed / routine mutating verbs that are not destructive shapes
        "kubectl apply -f prod.yaml",
        "kubectl diff -f prod.yaml",
        "kubectl create namespace staging",
        "kubectl edit deployment web",
        "kubectl scale deployment web --replicas=3",
        "kubectl rollout restart deployment web",
        // a single pod delete is routine (controller-managed, ephemeral)
        "kubectl delete pod web-abc123",
        "kubectl delete configmap app-config",
        "kubectl delete deployment web",
        // a pod literally NAMED `pv` must not look like a PersistentVolume delete
        "kubectl delete pod pv",
        // a namespace/release literally NAMED delete-me is not the operation
        "kubectl get namespace delete-me",
        "kubectl describe pvc delete-me",
        // --all-namespaces is a read scope, not the bulk --all delete flag
        "kubectl get pods --all-namespaces",
        // helm read/reviewed verbs
        "helm install my-release ./chart",
        "helm upgrade my-release ./chart",
        "helm list",
        "helm status my-release",
        // a release NAMED with an embedded 'delete' is not the uninstall verb
        "helm status my-delete-release",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
