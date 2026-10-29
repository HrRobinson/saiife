# Azure Resource Manager connector

The `azure-arm` connector reaches Azure Resource Manager (list resource
groups, resources and VMs; restart a VM) through `saiifed`. The daemon mints
an OAuth2 access token for a service principal in its vault; the agent never
sees the client secret or the token. The manifest is
`crates/broker/connectors/azure-arm.toml`, embedded at build time.

- Base URL `https://management.azure.com`.
- Auth: `azure_sp`, scope `https://management.azure.com/.default`. The vault
  entry is an `azure_sp` secret (`tenant_id`, `client_id`,
  `client_secret`). Tokens come from
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`; set
  `[services.<name>.cloud] authority_host` for a sovereign cloud.
- `api-version` is fixed per operation: `2021-04-01` for the
  `Microsoft.Resources` operations and `2025-04-01` for
  `Microsoft.Compute`. A call that sets it is refused.
- No request header is accepted from the agent.
- Answers carry `nextLink`, a full URL, which saiife does not follow: narrow
  the list with `$filter` and `$top`.
- Subscription ids, resource group and VM names are accepted in lower case
  only. Azure ignores their case, while `allow` compares case exactly, so
  each resource has one spelling in the qualifier.
- Vendor reference:
  <https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list>,
  <https://learn.microsoft.com/en-us/rest/api/resources/resources/list>,
  <https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list-all>,
  <https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/restart>.

## Operations

| Operation | Capability | Kind | Request | Azure action |
|---|---|---|---|---|
| `resourcegroups.list` | `resourcegroups:read` | read | `GET /subscriptions/{subscription_id}/resourcegroups` | `Microsoft.Resources/subscriptions/resourceGroups/read` |
| `resources.list` | `resources:read` | read | `GET /subscriptions/{subscription_id}/resources` | `Microsoft.Resources/subscriptions/resources/read` |
| `vms.list` | `vms:read` | read | `GET /subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines` | `Microsoft.Compute/virtualMachines/read` |
| `vms.restart` | `vms:write` | write | `POST .../resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/restart` | `Microsoft.Compute/virtualMachines/restart/action` |

The qualifier is the Azure resource id: `/subscriptions/{subscription_id}`
for the lists, and the VM's id for `vms.restart`.

Parameters:

- `resourcegroups.list`: `$filter` and `$top`.
- `resources.list`: `$filter`, `$expand` and `$top`.
- `vms.list`: `statusOnly`.

```bash
saiife api azure resourcegroups.list subscription_id=00000000-1111-2222-3333-444444444444
saiife api azure vms.restart subscription_id=00000000-1111-2222-3333-444444444444 resource_group=web vm_name=vm1
```

## The secret

The vault kind is `azure_sp`, with the fields `tenant_id`, `client_id` and
`client_secret` of an app registration (service principal).

```sh
saiife secret add azure-reader --kind azure_sp --service azure
saiife connect azure --connector azure-arm --secret azure-reader
```

The daemon gets a token with the client-credentials flow and keeps it in
memory only. The default authority is `login.microsoftonline.com`; set
`[services.azure.cloud] authority_host` to `login.microsoftonline.us` or
`login.chinacloudapi.cn` for a sovereign cloud.

## Minimum permissions in Azure

Assign roles to the service principal at the narrowest scope that works.

| Capability | Operations | Azure action | Smallest built-in role |
|---|---|---|---|
| `resourcegroups:read` | `resourcegroups.list` | `Microsoft.Resources/subscriptions/resourceGroups/read` | Reader |
| `resources:read` | `resources.list` | `Microsoft.Resources/subscriptions/resources/read` | Reader |
| `vms:read` | `vms.list` | `Microsoft.Compute/virtualMachines/read` | Reader |
| `vms:write` | `vms.restart` | `Microsoft.Compute/virtualMachines/restart/action` | Virtual Machine Contributor, on one resource group |

## Known limits

- **Paging.** An answer that is cut off carries `nextLink`, a full URL.
  saiife does not follow it and has no `next` parameter for ARM. Narrow the
  list with `$filter` and `$top` instead.
- There is no STS mode for Azure: `mode = "sts"` on this connector is a
  config error.
- The `api-version` values are pinned in the manifest; an Azure change needs
  a new saiife version.

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny. Both
policies go in `/etc/saiife/policy.d/azure.toml`.

## Suggested policy: read-only

```toml
[services.azure]
connector = "azure-arm"
secret = "azure-reader"
allow = ["resourcegroups:read", "resources:read", "vms:read"]
```

`vms.restart` is denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.azure]
connector = "azure-arm"
secret = "azure-ops"
allow = ["resourcegroups:read", "resources:read", "vms:read"]
ask   = ["vms:write"]
```

## Locked mode

In locked mode (Linux) the agent user reaches Azure only through `saiifed`.
The client secret lives in the daemon's vault (`saiife secret add
azure-reader --kind azure_sp --service azure`); the secret and every minted
token are masked in answers and never reach the agent's environment, files or
audit records. Every call is one `connector` audit record.

Give the service principal only the Azure roles the policy needs (for
example Reader, plus Virtual Machine Contributor on one resource group), so a
policy mistake is bounded by the principal.
