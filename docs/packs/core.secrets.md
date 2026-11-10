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

**Writing credential files.** Overwriting a login file swaps in someone
else's account, and a key added to `authorized_keys` can log in as you. So
writing these is blocked too, through the file tools (Write, Edit) and
through shell commands that write them (`cp`, `mv`, `tee`, `dd`, `ln`,
`install`, `rsync`, `rm`, `>`/`>>` redirects, and in cmd and PowerShell
`copy`, `move`, `Copy-Item`, `Set-Content`, `Add-Content`, `Out-File`):

- Every file above except the `.env` files and `/proc/<pid>/environ`.
- `~/.ssh/authorized_keys` and `authorized_keys2`, in any home. Reading
  them stays allowed.
- `~/.npmrc` (a project's own `.npmrc` stays writable).
- On Windows, the stored credentials, the vaults and the DPAPI keys under
  `AppData`, and the GitHub CLI and Google Cloud login files there.
- The folders that hold them in your own home, and every folder above:
  removing, moving or replacing `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker`,
  `~/.config/gh` (and so on) is blocked, for example `rm -rf ~/.aws`,
  `mv ~/.ssh ~/.ssh.bak`, `ln -s /tmp/x ~/.kube` or `cp -r x/. ~/.ssh/`.
  Extracting an archive into one of them or into your home is blocked too,
  with `tar`, `bsdtar`, `unzip`, `cpio -i` or `7z x` (`tar -xf x.tar -C ~`,
  `cd ~ && unzip x.zip`): what it holds is not known. So is an extract that
  may write anywhere, wherever it runs: absolute or `../` names
  (`tar -P`, `unzip -:`, `7z x -spf`, `-snl`), `cpio -i` without
  `--no-absolute-filenames`, and an extract with an option saiife does not
  know (an abbreviated long option included). Listing
  them (`ls ~/.ssh`), `chmod 700 ~/.ssh` and writing other files in them
  (`~/.ssh/known_hosts`, `~/.ssh/config`, `~/.aws/config`) stay allowed.

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
- The personal broker's vault key in the keychain: `secret-tool lookup` or
  `search` naming saiife, `security find-generic-password` naming saiife,
  `security dump-keychain`, and `gdbus`, `busctl`, `dbus-send` or `qdbus`
  calls to `org.freedesktop.secrets` with `GetSecret` or `SearchItems`. This
  is a mistake layer: a script of the same user can still call the Secret
  Service.

## Allowed on purpose

- Example env files: `.env.example`, `.env.sample`, `.env.dist`,
  `.env.defaults`, `.env.template`. They hold no secrets.
- SSH public keys (`~/.ssh/id_*.pub`) and `~/.ssh/config`.
- Writing `.env` files (`cp .env.example .env`, `echo 'DEBUG=1' >> .env`)
  and a project's `.npmrc`.
- Changing the mode or owner of a credential file (`chmod 600 ~/.ssh/id_rsa`,
  `chown`, `chgrp`, `chattr`).
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
- Replacing another user's credential folders as a whole (`rm -rf
  /root/.ssh`): the folder rules name your own home. Their files are covered.
- Other extractors and installers (`git clone` into a folder, `pip`, a
  script) that may write a credential folder.
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

The limits that apply to every pack are in
[Limits of the guard as a whole](../threats.md#limits-of-the-guard-as-a-whole).

## Examples

```saiife-examples
deny secret-tool lookup application saiife
deny security find-generic-password -s saiife -w
allow secret-tool lookup application other
allow security find-generic-password -s github
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
deny cp /tmp/evil /home/me/.aws/credentials
deny tee -a /home/me/.ssh/authorized_keys < /tmp/key.pub
allow cat /home/me/.ssh/authorized_keys
allow chmod 600 /home/me/.ssh/id_rsa
```
- A home directory that is unknown or not an absolute path. saiife takes it
  from `HOME`, or from the user database when `HOME` is unset or empty; if the
  result is still not absolute (for example `HOME=.`), the rules for `~/...`
  paths (SSH keys, cloud logins, the agents' login tokens) are inactive, and
  `saiife status` lists them as inactive. The `.env` rules still apply.
