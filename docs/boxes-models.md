# Models in a box

A box runs one coding agent. The agent never holds your model key. It talks to a gateway on the host (127.0.0.1:3129 in the box), which replaces a per-box placeholder with the real key and forwards the call to the provider. The key stays in the vault.

## Providers and templates

| Provider | Template | Status | Vault service |
| --- | --- | --- | --- |
| Anthropic | `claude-code` | supported | `box-model-anthropic` |
| OpenAI | `codex` | beta | `box-model-openai` |
| Google | `gemini` | beta | `box-model-google` |

The `codex` and `gemini` images are built only when you pass `--with codex` or `--with gemini` to the image build, with their versions pinned in `assets/box/recipe.toml`.

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

Use a billing-enabled API key for private code. On the free tier, Google may use prompts and responses to improve its products. `saiife box templates` and `saiife box spawn --template gemini` print this notice.

## What the gateway forwards

The gateway forwards only an exact list of model API calls (method, path and query) per provider. Any other call gets 403. Each refused call is logged in the audit as `model_denied` with reason `path_not_allowed`, with its method and path. The owner smoke (`scripts/box-smoke.sh --only claude|codex|gemini`) lists these as `model_paths_<agent>`.

## Before release (TODO)

The legacy `box-model` vault service is still accepted on the Anthropic route as an alias, so an existing entry keeps working. Decide before release: drop the alias, or keep it.
