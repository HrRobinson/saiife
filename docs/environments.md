# Environments

An environment is a named overlay on the system config: it adds guard packs
and overrides settings of services the base config already defines. Use it
for staging and production sides of the same service, or to make a policy
stricter (or, on purpose, looser) for one scope.

```toml
# /etc/saiife/config.toml
[environments.staging]
services.shopify.secret = "shopify-staging"
services.shopify.params = { shop = "acme-staging" }

[environments.prod]
guard.packs = ["iac.terraform", "db.postgres"]
services.shopify.ask = ["products:write"]

[[scope]]
name = "agents-prod"
users = ["group:agents"]
services = ["shopify"]
env = "prod"
```

## What an environment can change

- **Packs.** `guard.packs` is added to the base list. An environment cannot
  remove a pack, and cannot turn off a default-on pack.
- **Service settings.** Under `services.<name>`: `secret`, `params`, `fixed`,
  `allow`, `ask`, `deny`, `rule`, `limits` and `redact`. A key that is
  present replaces the base value, except `params`, `fixed` and `limits`,
  which merge key by key. `allow` replaces the whole list, so an environment
  may widen what the base policy allowed as well as narrow it. Treat the
  definition of an environment as policy, not as a safe default.
- **Never** what the service talks to: `connector`, `base_url`, `auth` and
  `operation` are not keys of an environment, and an unknown key is a config
  error. An override for a service the base config does not define is also an
  error.

The names of environments use `a-z`, `0-9`, `_` and `-`, 1 to 64 characters.
`[environments]` is read only from the system `config.toml`; in a
`policy.d/*.toml` file or a project file it is refused.

## Which environment applies

**Locked mode (Linux).** The admin binds an environment to a scope with
`env = "prod"` in the `[[scope]]`. A uid has exactly one scope, so it has
exactly one environment. The project path never chooses it: an `env` in
`.saiife/config.toml` is ignored in locked mode, and a malformed `env` value
there is still a bad request, not a fallback. The environment in force is
part of the effective-policy hash, so every record shows which one applied.

**Developer mode and the personal broker.** `saiife env use <name>` writes
`env = "<name>"` into `.saiife/config.toml`. `saiife api` sends that `env` to
the personal broker, whose own config defines the environments. A
well-formed `env` that no environment defines falls back to the base config
with a warning in developer mode and the personal broker, and is ignored in
locked mode.

In developer and personal-broker mode an environment changes connector calls
only; its guard packs apply in locked mode. The guard hook and `saiife policy
show` do not read the project's `env` there, and `policy show` says so on its
last line.

## Commands

```
saiife env list [--json]
saiife env use <name>                    # developer mode
saiife env use <name> --scope <scope>    # locked mode, root only
```

`env list` shows each environment, its pack and service counts, the scopes
bound to it, and `*` for the one that applies to you. `env use --scope` edits
the root-owned config and asks the daemon to reload, so it needs root:
switching a scope to a looser environment is an admin act.
