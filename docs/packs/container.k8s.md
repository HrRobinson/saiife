# Container: kubernetes (container.k8s)

This pack stops Kubernetes commands (`kubectl`, `helm`) with a large or
permanent effect: deleting a namespace or stored data, deleting everything
in a manifest or of one kind, emptying a node, and uninstalling a Helm
release. Reading and routine changes are never blocked.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack container.k8s`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["container.k8s"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `kubectl drain`. It empties a node and moves every pod off it.
- `kubectl delete namespace`, `kubectl delete pv` and `kubectl delete pvc`
  (persistent volumes and claims). Everything inside goes with them, and
  stored data is lost.
- `kubectl delete -f <file>`. It removes every resource described in the
  file.
- `kubectl delete ... --all`. It removes every resource of that kind at once.
- `helm uninstall` (and the older `helm delete`). It removes a release and
  everything it created.

These rules also apply with options before the verb
(`kubectl -n prod delete pvc ...`, `kubectl --context prod drain ...`).

## Allowed on purpose

- Reading: `kubectl get`, `describe`, `logs`, `helm list`, `helm status`.
- Routine changes: `kubectl apply`, `diff`, `create`, `edit`, `scale`,
  `rollout`, `helm install`, `helm upgrade`.
- Deleting a single pod, deployment or config map
  (`kubectl delete pod web-abc123`). Kubernetes usually recreates pods, and
  these hold no stored data.
- A resource that is only named like a kind, for example a pod called `pv`.

## Not covered

- Single deletes of other kinds (deployments, services, secrets) are allowed.
- `kubectl apply` of a changed manifest can still remove or replace things;
  it is allowed.
- `kubectl cordon`, `kubectl scale --replicas=0` and `helm rollback` are
  allowed.
- Reading Kubernetes secrets is covered by `core.secrets`, not by this pack.

## Examples

```saiife-examples
deny kubectl delete namespace prod
deny kubectl delete pvc data-claim
deny kubectl delete -f prod.yaml
deny kubectl delete pods --all
deny kubectl drain node-1
deny helm uninstall my-release
deny kubectl -n prod delete pvc data-claim
allow kubectl get pods
allow kubectl apply -f prod.yaml
allow kubectl delete pod web-abc123
allow kubectl get pods --all-namespaces
allow helm upgrade my-release ./chart
```
