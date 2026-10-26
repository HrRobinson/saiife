# GitHub connector

Connector id `github`. It calls the GitHub REST API at `https://api.github.com`
(host `api.github.com`) with a bearer token from the vault. The manifest is
`crates/broker/connectors/github.toml`; paths were checked against
<https://docs.github.com/en/rest>.

## Setup

```sh
# the token (a fine-grained personal access token or a GitHub App installation token)
saiife secret add github-main --kind token --service github
```

```toml
[services.github]
connector = "github"
secret = "github-main"
```

## Operations and capabilities

Every operation carries the qualifier `repo={owner}/{repo}`, filled from the
call's `owner` and `repo` parameters. So the capability for
`saiife api github issues.create owner=acme repo=web` is
`issues:write:repo=acme/web`, and a rule like `issues:write:repo=acme/*`
scopes a write to one organization.

| Operation        | Method and path                                     | Capability     | Notes |
| ---------------- | --------------------------------------------------- | -------------- | ----- |
| `repos.get`      | `GET /repos/{owner}/{repo}`                         | `repos:read`   | |
| `issues.list`    | `GET /repos/{owner}/{repo}/issues`                  | `issues:read`  | query `state` (`open`, `closed`, `all`), `labels`, `assignee`, `since`, `per_page` (1..100), `page`; Link-header pagination |
| `issues.get`     | `GET /repos/{owner}/{repo}/issues/{issue_number}`   | `issues:read`  | |
| `issues.create`  | `POST /repos/{owner}/{repo}/issues`                 | `issues:write` | JSON body |
| `issues.comment` | `POST /repos/{owner}/{repo}/issues/{issue_number}/comments` | `issues:write` | JSON body |
| `pulls.list`     | `GET /repos/{owner}/{repo}/pulls`                   | `pulls:read`   | query `state`, `head`, `base`, `per_page`, `page`; Link-header pagination |
| `pulls.get`      | `GET /repos/{owner}/{repo}/pulls/{pull_number}`     | `pulls:read`   | |
| `pulls.create`   | `POST /repos/{owner}/{repo}/pulls`                  | `pulls:write`  | JSON body |

No operation has an `amount`. Note that GitHub's issues endpoint also lists
pull requests, so `issues:read` can see them.

`owner` and `repo` are single path segments: a value with `/`, `..` or a
backslash is refused. Pagination: `issues.list` and `pulls.list` return
`next` (the `page` and `per_page` for the next page) taken from the `Link`
header.

## Headers

GitHub documents `Accept: application/vnd.github+json` and
`X-GitHub-Api-Version: 2022-11-28`. The manifest format has no fixed headers,
so the connector only lists `Content-Type`, `Accept` and `X-GitHub-Api-Version`
in `request_headers`, and the caller sends them. `Authorization`, `Cookie` and
`Host` from the caller are always dropped.

## Suggested policy: read-only

```toml
[services.github]
connector = "github"
secret = "github-main"
allow = ["repos:read", "issues:read", "pulls:read"]
```

Everything else, including every write, is denied (`default_deny`).

## Suggested policy: every write under `ask`

```toml
[services.github]
connector = "github"
secret = "github-main"
allow = ["repos:read", "issues:read", "pulls:read"]
ask   = ["issues:write", "pulls:write"]
```

Until plan 11 (approvals) an `ask` is answered as a deny with
`rule = "approval_not_available"`, so this policy behaves like the read-only
one today and starts asking when approvals ship.

To open writes on one organization only:

```toml
allow = ["repos:read", "issues:read", "pulls:read", "issues:write:repo=acme/*"]
deny  = ["issues:write:repo=acme/infra"]
```

Qualifier matching: in `allow`, `*` stays within one `/` level and the match is
case-exact, so `acme/*` allows `acme/web` and not `other/web`, `ACME/web` or
`acme/web/x`. A qualified `allow` never matches a call that has no qualifier.
`deny` and `ask` patterns are broader: `*` crosses `/`, case is ignored, and a
missing qualifier matches. A matching `deny` wins over `ask`, and `ask` over
`allow`.

## Limits

Limits count requests that were sent upstream. Reasonable starting values:

```toml
[services.github.limits]
requests_per_minute = 60
writes_per_hour = 30
```

GitHub also rate-limits the token itself (see the vendor's rate-limit docs);
a 403 or 429 from GitHub is passed on with `X-Saiife-Upstream-Status`.

## Locked mode

In locked mode the token lives in the vault of the saiife daemon and never
reaches the agent. The agent calls `saiife api github <operation> k=v ...` or
the gateway socket; the daemon checks the policy from `/etc/saiife`, adds the
`Authorization: Bearer ...` header and sends the request to `api.github.com`
only. A project `.saiife/config.toml` can add `deny` and `ask` entries for this
service, never `allow`. Redirects are followed to the same host only, and the
token is masked in everything that comes back. Locked mode needs Linux in this
version.

## Tests

`crates/broker/tests/github.rs` (golden requests in `tests/golden/github_*.http`,
response shapes in `tests/fixtures/github/`). The fixtures follow the vendor's
documented examples and were not fetched.
