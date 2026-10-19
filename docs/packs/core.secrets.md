# Core: secrets (core.secrets)

This pack stops an agent from reading secrets: files that hold passwords,
keys or tokens, commands that print every environment variable, and commands
that print a secret from a secret manager or a cloud tool. A secret that an
agent has read can end up in its chat history, logs or the AI provider's
systems.

## On by default

Yes. It is always on. It cannot be turned off in `.saiife/config.toml`: the
`packs` list there only adds opt-in packs.

## Blocked

**Secret files.** Reading these files is blocked, both through the agent's
own file tools and through shell commands that read them (`cat`, `grep`,
`less`, `cp`, `scp`, `base64`, uploads with `curl -d @file`, `source`):

- `.env`, `.env.*` (for example `.env.local`, `.env.production`) and `.envrc`
  files, in any folder.
- SSH private keys (`~/.ssh/id_*`).
- Cloud and tool logins: `~/.aws/credentials` and the AWS SSO and CLI caches,
  the Google Cloud folder `~/.config/gcloud/`, the Azure folder `~/.azure/`,
  `~/.kube/config`, `~/.docker/config.json`, the GitHub CLI token file
  `~/.config/gh/hosts.yml`, `.vault-token` and `.git-credentials`.
- Package and login password files: `.npmrc`, `.pypirc`, `.netrc`.
- The environment of a running process (`/proc/<pid>/environ`).
- The agents' own login tokens: Claude Code's `.credentials.json` (in
  `~/.claude/` or `$CLAUDE_CONFIG_DIR`), Codex's `auth.json` (in `~/.codex/`
  or `$CODEX_HOME`) and Gemini CLI's `~/.gemini/oauth_creds.json`. With these
  an agent could act as you elsewhere.

**Printing every environment variable.** A bare `env`, `printenv` without a
name, a bare `set`, `export -p`, `declare -x`/`declare -p` (and `typeset`),
and `ps e`. They print tokens and keys along with everything else.

**Secret managers and cloud tools.** Commands that print or create a secret:

- AWS: `secretsmanager get-secret-value`, `ssm get-parameter --with-decryption`,
  `iam create-access-key`, `sts get-session-token`, `sts assume-role`,
  `sts get-federation-token`, `configure export-credentials`, and
  `configure get` of a name that contains secret, token, password or key.
- Google Cloud: `secrets versions access`, `auth print-access-token`,
  `auth print-identity-token`, `config config-helper`,
  `iam service-accounts keys create`.
- Azure: `keyvault secret show`/`download`, `account get-access-token`.
- Kubernetes: `kubectl get secret` with an output format that shows the
  values (`-o yaml`, `-o json`, `jsonpath`, templates), `kubectl get --raw`
  of secrets, and `kubectl config view --raw`/`--flatten`.
- HashiCorp Vault (`vault read`, `vault kv get`), 1Password (`op read`,
  `op item get`), Doppler (`doppler secrets`).
- The GitHub CLI token (`gh auth token`, `gh auth status --show-token`) and
  git's stored passwords (`git credential fill`, credential helper `get`).

## Allowed on purpose

- Example env files: `.env.example`, `.env.sample`, `.env.dist`,
  `.env.defaults`, `.env.template`. They hold no secrets.
- SSH public keys (`~/.ssh/id_*.pub`) and `~/.ssh/config`.
- Printing one named variable (`printenv HOME`) and running a command with
  extra variables (`env FOO=1 npm test`).
- `kubectl describe secret` (Kubernetes hides the values) and
  `kubectl get secrets` without a value-showing output format (names only).
- `aws configure get region` and other non-secret settings.
- Listing secrets without their values, for example
  `aws secretsmanager list-secrets`.

## Not covered

What the agent does inside its own programs and some indirect reads are not
seen:

- A script the agent writes and then runs.
- A recursive read of a folder that holds a secret, for example
  `grep -r KEY .` or `cp -r ~/.ssh x`.
- A secret read from git history: `git show HEAD:.env`.
- Reads through `find ... -exec cat {} +` and through `xargs`.
- Gemini CLI's `read_many_files` with a broad pattern (`**/*`). This relies on
  Gemini's own handling of git-ignored files.
- A recursive search (`Grep`, `rg`) of a whole folder without a file pattern
  is not judged file by file. `rg` skips hidden and git-ignored files by
  default.
- `aws configure get` is blocked only for names that contain secret, token,
  password or key.
- A file name built at run time and hidden in `$(...)`, for example
  `cat $(ls)` or an escape-encoded name like `cat $(echo -e '.\x65nv')`, is
  skipped without a note. An escape-encoded name is a deliberate bypass.
- A relative `CLAUDE_CONFIG_DIR` used by the agent is not resolved against
  the folder the hook runs in.
- `CLAUDE_CONFIG_DIR=/x cat /x/.credentials.json`, which sets the folder on
  the same line, is not covered.
- Gemini CLI's `GEMINI_CLI_HOME` folder is not covered.
- When saiife cannot tell your home folder (no `HOME` set), the rules written
  for the home folder (`~/.claude/.credentials.json`, `~/.codex/auth.json`,
  `~/.gemini/oauth_creds.json`) do not apply. The same is true for the
  `$CLAUDE_CONFIG_DIR` and `$CODEX_HOME` rules when those are not set.
  `saiife status` lists such rules as "inactive here".

It also blocks too much in a few cases. This is the safe direction:

- `source .env && npm start` and `set -a; . ./.env` are blocked, because they
  read `.env`. Run them yourself, or let the program load `.env` itself.

### Limits of the guard as a whole

These apply to every pack:

- When a command line names `IFS` (the shell setting for how text is split
  into words), saiife cannot be sure how values from `$(...)` split. It allows
  the command unless a rule blocks it, and records it in the audit log as
  `error_allowed`.
- A here-document inside `$(...)` ends at a line that starts with its end word
  and holds a `)`, as in bash 5.3. Older bash and zsh may end it elsewhere.
- zsh 5.9 and dash read three such here-document shapes differently from
  bash. There, saiife may block a command that those shells would treat as
  plain text. This is the safe direction.

## Examples

```saiife-examples
deny env
deny printenv
deny export -p
deny ps eww
deny aws secretsmanager get-secret-value --secret-id prod/db
deny gcloud auth print-access-token
deny kubectl get secret db -o yaml
deny vault kv get secret/prod
deny gh auth token
allow printenv HOME
allow env FOO=1 npm test
allow kubectl describe secret db
allow kubectl get secrets
allow aws configure get region
allow aws secretsmanager list-secrets
```
