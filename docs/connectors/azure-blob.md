# Azure Blob Storage connector

The `azure-blob` connector reaches Azure Blob Storage (list, get, put and
delete blobs) through `saiifed`. The daemon mints an OAuth2 access token for
a service principal in its vault; the agent never sees the client secret or
the token. The manifest is `crates/broker/connectors/azure-blob.toml`,
embedded at build time.

- Base URL `https://{account}.blob.core.windows.net`. `account` is a service
  param set by the admin, never by the agent (3 to 24 lower-case letters and
  digits).
- Auth: `azure_sp`, scope `https://storage.azure.com/.default`. The vault
  entry is an `azure_sp` secret (`tenant_id`, `client_id`,
  `client_secret`).
- Each operation sends `x-ms-version: 2026-04-06`; `blobs.put` also sends
  `x-ms-blob-type: BlockBlob`. These win over anything the agent sends.
- Request headers the agent may send: `Content-Type` and `Range`. Headers
  that change what a call does (`x-ms-copy-source`,
  `x-ms-delete-snapshots`, lease, tier, encryption, tag and immutability
  headers) are dropped.
- Vendor reference:
  <https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs>,
  <https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob>,
  <https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob>,
  <https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob>,
  <https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services>.

## Operations

| Operation | Capability | Kind | Request | Data action |
|---|---|---|---|---|
| `blobs.list` | `blobs:read` | read | `GET /{container}?restype=container&comp=list` | `.../containers/blobs/read` |
| `blobs.get` | `blobs:read` | read | `GET /{container}/{blob}` | `.../containers/blobs/read` |
| `blobs.put` | `blobs:write` | write | `PUT /{container}/{blob}` | `.../containers/blobs/write` |
| `blobs.delete` | `blobs:delete` | delete | `DELETE /{container}/{blob}` | `.../containers/blobs/delete` |

The data actions start with
`Microsoft.Storage/storageAccounts/blobServices`. The qualifier is
`{container}` for the list and `{container}/{blob}` for the blob operations.

Parameters:

- `container`: a container name (lower case, 3 to 63 characters).
- `blob`: a blob name, which may hold `/`. Each segment is percent-encoded
  and `/` is kept. An empty name, an empty segment, a `.` or `..` segment, a
  backslash or a control character is refused.
- `blobs.list`: `prefix`, `delimiter`, `marker` and `maxresults` (1 to 5000).
- `blobs.put`: the body is the blob's data, sent as it is.

Answers are XML (or the blob's bytes), passed through as text and masked.
`blobs.list` is paged by hand: pass the answer's `NextMarker` as `marker`.

```bash
saiife api blob blobs.list container=logs prefix=2026/
saiife api blob blobs.get container=logs blob=2026/10/report.json
```

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny. In
`allow`, a single `*` does not cross `/`; use a trailing `**`. Both policies
go in `/etc/saiife/policy.d/blob.toml`.

## Suggested policy: read-only

```toml
[services.blob]
connector = "azure-blob"
secret = "azure-storage"
allow = ["blobs:read:logs", "blobs:read:logs/**"]

[services.blob.params]
account = "acmedata"
```

Puts and deletes are denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.blob]
connector = "azure-blob"
secret = "azure-storage"
allow = ["blobs:read:logs", "blobs:read:logs/**"]
ask   = ["blobs:write", "blobs:delete"]

[services.blob.params]
account = "acmedata"
```

## Locked mode

In locked mode (Linux) the agent user reaches Blob Storage only through
`saiifed`. The client secret lives in the daemon's vault (`saiife secret add
azure-storage --kind azure_sp --service blob`); the secret and every minted
token are masked in answers and never reach the agent's environment, files or
audit records. Every call is one `connector` audit record.

Give the service principal a Storage Blob Data role scoped to the containers
the policy names, so a policy mistake is bounded by the principal.
