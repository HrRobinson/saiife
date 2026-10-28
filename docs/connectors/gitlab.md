# GitLab connector

Connector id `gitlab`, REST API v4, built into `saiife-broker`
(`crates/broker/connectors/gitlab.toml`). It works with gitlab.com and with
self-managed instances. The service starts with everything denied: each
capability below needs an `allow` (or `ask`) entry in the policy.

Paths follow the GitLab REST reference (<https://docs.gitlab.com/api/>). This
page and the test fixtures were written offline, in the documented shape;
check them against the reference when GitLab changes an endpoint.

## Setup

```sh
saiife secret add gitlab-main --kind token --service gitlab   # a personal or project access token
```

The token goes out only in the `PRIVATE-TOKEN` header. Give it the narrowest
scope you can (`read_api` for the suggested read-only policy).

`host` is the instance's bare hostname, for example `gitlab.com` or
`gitlab.acme.com`. The admin sets it in the service config; the agent cannot.
It must be lower case, with no scheme, port, path or user part, and it is the
only host the service ever contacts. A redirect to another host is refused.

**`project_id` is the numeric project id**, not the `group/project` path. A
URL-encoded path would need `%2F`, which path parameters refuse. Find the id
on the project's overview page (under the project name), in
Settings, General, or with `GET /projects?search=<name>` on your instance.

## Operations

| Operation | Capability | Kind | Request |
|---|---|---|---|
| `projects.get` | `projects:read` | read | `GET /projects/{project_id}` |
| `issues.list` | `issues:read` | read | `GET /projects/{project_id}/issues`; query `state` (`opened`, `closed`, `all`), `labels`, `search`, `per_page` (1..100), `page` |
| `issues.get` | `issues:read` | read | `GET /projects/{project_id}/issues/{issue_iid}` |
| `issues.create` | `issues:write` | write | `POST /projects/{project_id}/issues`, JSON body |
| `issues.comment` | `issues:write` | write | `POST /projects/{project_id}/issues/{issue_iid}/notes`, JSON body (`{"body": "..."}`) |
| `merge_requests.list` | `merge_requests:read` | read | `GET /projects/{project_id}/merge_requests`; query `state` (`opened`, `closed`, `locked`, `merged`, `all`), `per_page`, `page` |
| `merge_requests.get` | `merge_requests:read` | read | `GET /projects/{project_id}/merge_requests/{mr_iid}` |
| `pipelines.list` | `pipelines:read` | read | `GET /projects/{project_id}/pipelines`; query `status`, `ref`, `per_page`, `page` |

Notes:

- Every operation carries the qualifier `project={project_id}`, so a rule can
  be limited to one project: `allow = ["issues:read:project=42"]`.
- `project_id`, `issue_iid` and `mr_iid` are integers.
- Agents may send `Content-Type` and `Accept`; every other request header is
  dropped.
- **Pagination** is the `Link` header. The `rel="next"` URL carries `page`;
  pass it back as `page=...` (with the same `per_page`).

## Suggested policy: read-only

`/etc/saiife/policy.d/gitlab.toml`:

```toml
[services.gitlab]
connector = "gitlab"
secret = "gitlab-main"
params = { host = "gitlab.acme.com" }
allow = ["projects:read", "issues:read", "merge_requests:read", "pipelines:read"]

[services.gitlab.limits]
requests_per_minute = 60
```

## Suggested policy: every write under `ask`

```toml
[services.gitlab]
connector = "gitlab"
secret = "gitlab-main"
params = { host = "gitlab.acme.com" }
allow = ["projects:read", "issues:read", "merge_requests:read", "pipelines:read"]
ask   = ["issues:write"]

[services.gitlab.limits]
requests_per_minute = 60
writes_per_hour = 30
```

## Limits

- Writes count toward `writes_per_hour`.
- GitLab's own rate limits are separate; a `429` from GitLab is passed on.
- There are no merge, close or delete operations in this version.

## Locked mode

In locked mode (`/etc/saiife/config.toml` with `locked = true`) the token
lives in the root-owned vault and never reaches the agent; calls go through
the gateway, which adds it. A project config can add `deny` and `ask`
entries but cannot add an `allow` or change the secret or the host. Use
`saiife api gitlab issues.list project_id=42 state=opened`, or the gateway at
`/v1/api`; the exit codes are those of `saiife api` (2 denied, 4 limit
reached).
