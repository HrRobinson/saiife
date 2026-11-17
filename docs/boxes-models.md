# Models in a box

A box runs one coding agent. The agent never holds your model key. It talks to a gateway on the host (127.0.0.1:3129 in the box), which replaces a per-box placeholder with the real key and forwards the call to the provider. The key stays in the vault.

## Providers and templates

| Provider | Template | Status | Vault service |
| --- | --- | --- | --- |
| Anthropic | `claude-code` | supported | `box-model-anthropic` |
| OpenAI | `codex` | beta | `box-model-openai` |
| Google | `gemini` | beta | `box-model-google` |

The `codex` and `gemini` images are built only when you pass `--with codex` or `--with gemini` to the image build, with their versions pinned in `assets/box/recipe.toml`.

A rebuilt image is not used until you import it and make it the default. The build writes `base-<sha256>.raw` and its `.json` manifest to the output directory. Then run:

```
saiife box image import <out-dir>/base-<sha256>.raw --default
```

or import it without `--default`, and then `saiife box image default base-<sha256>`. A box whose image lacks its agent refuses to boot and prints these commands. Gemini also needs the `[node]` pin to be set; Codex needs only `[codex]`.

saiife's guard hooks in a box are baked into the image as each agent's root-owned managed settings: `/etc/claude-code/managed-settings.json` for Claude Code (only managed hooks and permission rules, no MCP servers, no repo helper commands, the gateway URL, provider and proxy pinned), `/etc/codex/requirements.toml` and `/etc/codex/managed_config.toml` for Codex, and `/etc/gemini-cli/settings.json` for Gemini. A repo's own `.claude/settings.json` or `.claude/settings.local.json`, or an edit of `~/.claude/settings.json`, cannot turn them off. A Claude Code box on an image built before this change is refused with "rebuild the image (saiife box image build) and import it as default". Every saiife hook in a box runs as `/usr/bin/env -i PATH=... HOME=/home/agent USER=agent LANG=C.UTF-8 /usr/local/bin/saiife ...`, so no variable a repo or the agent sets reaches the guard; the pinned and blanked variables are a floor, and the VM and its host gateway stay the boundary.

## Store the key

```
saiife secret add anthropic --kind token --service box-model-anthropic --from-file <file>
saiife secret add openai    --kind token --service box-model-openai    --from-file <file>
saiife secret add gemini    --kind token --service box-model-google    --from-file <file>
```

Then `saiife box spawn --template claude-code|codex|gemini`. If the secret is missing, the answer names the service to use.

## Logins

Codex and Gemini take an API key only. A template that asks for `login = "subscription"` for either is refused when it is loaded:

```
login = "subscription" is not available for <kind>: only "api-key" (the gateway cannot hold its OAuth login yet; plan 42 D2)
```

ChatGPT sign-in for Codex and "Login with Google" for Gemini are not built.

## Gemini notice

Printed by `saiife box templates` and `saiife box spawn --template gemini`:

> Gemini: use a billing-enabled API key for private code; on the free tier Google may use prompts and responses to improve its products

## What the gateway forwards

The gateway forwards only the calls below, matched on method, exact path and query. Any other call gets 403. Each refused call is logged in the audit as `model_denied` with reason `path_not_allowed`, with its method and path. The owner smoke lists these as `model_paths_<agent>`. `{ID}` is one path segment of 1 to 128 characters from `A-Z a-z 0-9 . _ -` (not `.` or `..`). A query key not listed, a repeated key, or a value that fails its rule is refused.

| Provider | Method and path | Allowed query keys |
| --- | --- | --- |
| Anthropic | `POST /v1/messages` | `beta=true` |
| Anthropic | `POST /v1/messages/count_tokens` | `beta=true` |
| Anthropic | `GET /v1/models` | `beta=true`, `limit` (1 to 4 digits) |
| Anthropic | `GET /v1/models/{ID}` | `beta=true` |
| OpenAI | `POST /v1/responses` | none |
| OpenAI | `GET /v1/models` | `client_version` (up to 32 of `0-9 A-Z a-z . + -`) |
| OpenAI | `GET /v1/models/{ID}` | none |
| Google | `POST /v1beta/models/{ID}:streamGenerateContent` | `alt=sse` (required) |
| Google | `POST /v1beta/models/{ID}:generateContent` | none |
| Google | `POST /v1beta/models/{ID}:countTokens` | none |

When you bump the Codex pin in `assets/box/recipe.toml`, re-check this OpenAI list against the new Codex release (the owner smoke `model_paths_codex` lists the exact paths). For example `/v1/responses/compact` is not allow-listed because Codex 0.169 does not call it; a newer Codex that does would get 403 until it is added.

## Before release (TODO)

The legacy `box-model` vault service is still accepted on the Anthropic route as an alias, so an existing entry keeps working. Decide before release: drop the alias, or keep it.
