# Cloud: azure (cloud.azure)

This pack stops Azure command-line (`az`) operations that cannot be undone:
deleting resource groups, virtual machines, storage accounts and AKS
clusters, and changing role assignments. Commands that only look (`show`,
`list`) are never blocked.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack cloud.azure`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["cloud.azure"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `az group delete`. It deletes a resource group and every resource in it.
- `az vm delete`. It deletes the virtual machine for good.
- `az storage account delete`. It deletes the account and all data in it.
- `az aks delete`. It removes the Kubernetes cluster and its node pools.
- `az role assignment create`/`delete` and `az role definition delete`.
  These can give someone more access, or lock people out.
- Any other `az ... delete`. Check what it affects before you run it.

These rules also apply with global options before the command group
(`az --subscription prod group delete ...`) and through `sudo`.

## Allowed on purpose

- Read commands: `az group list`, `az vm show`, `az account show`,
  `az role assignment list`.
- A resource that is only named like an operation, for example a VM called
  `delete-me`.

## Not covered

- Only the `az` command is judged. Changes made in the Azure portal, through
  templates (ARM, Bicep, Terraform) or SDK scripts are not seen.
- Changes that are not deletes, such as `az vm stop`, `az vm deallocate` or
  `az resource update`, are allowed.
- Reading Azure secrets (Key Vault, access tokens) is covered by
  `core.secrets`, not by this pack.

## Examples

```saiife-examples
deny az group delete --name prod --yes
deny az vm delete --name web --resource-group prod
deny az storage account delete --name acct --resource-group prod
deny az aks delete --name cluster -g prod
deny az role assignment create --assignee x --role Owner --scope /subscriptions/s
deny az --subscription my-sub group delete --name prod --yes
allow az group list
allow az vm show --name delete-me -g prod
allow az role assignment list --assignee x
```
