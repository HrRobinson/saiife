# Google Cloud Storage connector

The `gcp-storage` connector reaches the Cloud Storage JSON API (list, get,
download, upload and delete objects) through `saiifed`. The daemon mints an
OAuth2 access token from a service-account key in its vault; the agent never
sees the key or the token. The manifest is
`crates/broker/connectors/gcp-storage.toml`, embedded at build time.

- Base URL `https://storage.googleapis.com`.
- Auth: `gcp_sa`, scope
  `https://www.googleapis.com/auth/devstorage.read_write`. The vault entry
  is a `gcp_sa` secret made from Google's service-account key file. Tokens
  come from `https://oauth2.googleapis.com/token` only; the key file's
  `token_uri` is ignored.
- Request headers the agent may send: `Content-Type` and `Range`.
  `Authorization`, `Cookie` and `Host` are always dropped.
- `userProject` (who pays for a requester-pays bucket) is not a parameter.
- Vendor reference:
  <https://cloud.google.com/storage/docs/json_api/v1/objects/list>,
  <https://cloud.google.com/storage/docs/json_api/v1/objects/get>,
  <https://cloud.google.com/storage/docs/json_api/v1/objects/insert>,
  <https://cloud.google.com/storage/docs/json_api/v1/objects/delete>,
  <https://cloud.google.com/storage/docs/access-control/iam-json>.

## Operations

| Operation | Capability | Kind | Request | IAM permission |
|---|---|---|---|---|
| `storage.objects.list` | `storage:read` | read | `GET /storage/v1/b/{bucket}/o` | `storage.objects.list` |
| `storage.objects.get` | `storage:read` | read | `GET /storage/v1/b/{bucket}/o/{object}` | `storage.objects.get` |
| `storage.objects.download` | `storage:read` | read | `GET /storage/v1/b/{bucket}/o/{object}?alt=media` | `storage.objects.get` |
| `storage.objects.insert` | `storage:write` | write | `POST /upload/storage/v1/b/{bucket}/o?uploadType=media&name={name}` | `storage.objects.create` |
| `storage.objects.delete` | `storage:delete` | delete | `DELETE /storage/v1/b/{bucket}/o/{object}` | `storage.objects.delete` |

The qualifier is `projects/_/buckets/{bucket}` for the list and
`projects/_/buckets/{bucket}/objects/{object}` (or `{name}` for an upload)
for the object operations.

The upload's qualifier is filled from the `name` query parameter. Query
parameters are not enforced as required, so an upload without `name` has no
object in its qualifier: a qualified `allow` does not match it, and the call
is denied (it fails closed). Google refuses such an upload as well.

Parameters:

- `object` and `name`: an object name, which may hold `/`. The whole name is
  one encoded path segment (`/` becomes `%2F`), so these operations are
  reachable by name only, not through `/v1/proxy`. An empty name, an empty
  segment, a `.` or `..` segment, a backslash or a control character is
  refused.
- `storage.objects.list`: `prefix`, `delimiter`, `maxResults` (1 to 1000),
  `pageToken`, `startOffset` and `endOffset`.
- `storage.objects.insert`: the body is the object's data, sent as it is.
  Send `Content-Type` for the object's type.

## Pagination

`storage.objects.list` uses cursor pagination: when the answer has
`nextPageToken`, saiife returns it as `next` (`next: pageToken=<token>` on
stderr, `X-Saiife-Next` over HTTP).

```bash
saiife api gcs storage.objects.list bucket=acme-data prefix=2026/
saiife api gcs storage.objects.download bucket=acme-data object=2026/10/report.json
saiife api gcs storage.objects.insert bucket=acme-data name=out/summary.txt --body @summary.txt
```

## Capabilities and policy

Policy order is deny, then ask, then allow; nothing matching means deny. In
`allow`, a single `*` does not cross `/`; use a trailing `**`. Both policies
go in `/etc/saiife/policy.d/gcs.toml`.

## Suggested policy: read-only

```toml
[services.gcs]
connector = "gcp-storage"
secret = "gcp-reader"
allow = ["storage:read:projects/_/buckets/acme-data", "storage:read:projects/_/buckets/acme-data/objects/**"]
```

Uploads and deletes are denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.gcs]
connector = "gcp-storage"
secret = "gcp-writer"
allow = ["storage:read:projects/_/buckets/acme-data", "storage:read:projects/_/buckets/acme-data/objects/**"]
ask   = ["storage:write", "storage:delete"]
```

## Locked mode

In locked mode (Linux) the agent user reaches Cloud Storage only through
`saiifed`. The key lives in the daemon's vault (`saiife secret add gcp-reader
--kind gcp_sa --service gcs --from-file key.json`); the key and every minted
token are masked in answers and never reach the agent's environment, files or
audit records. Every call is one `connector` audit record.

Grant the service account only the bucket roles the policy needs, so a
policy mistake is bounded by the account.
