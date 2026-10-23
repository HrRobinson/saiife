# Install saiife

saiife is one file. It makes no network calls. Only `install.sh` downloads anything.

## Quick install

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh
```

The script downloads the right build for your machine. It checks the SHA-256 checksum
and stops if it does not match. It installs `saiife` to `~/.local/bin`.
Make sure that folder is on your `PATH`.

Then check it works:

```sh
saiife --version
```

## Pin a version

Set `SAIIFE_VERSION` to install a specific release:

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | SAIIFE_VERSION=0.1.0 sh
```

To use another folder, set `SAIIFE_INSTALL_DIR`.

## Install for all users

Pass `--system` to install to `/usr/local/bin`. It asks for `sudo` only if that folder
is not writable. `--system` cannot be combined with `SAIIFE_INSTALL_DIR`; the script
stops with an error if both are set.

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh -s -- --system
```

## Manual install

If you do not want to pipe a script into your shell:

1. Open the [releases page](https://github.com/HrRobinson/saiife/releases).
2. Download the tarball for your platform and the `SHA256SUMS` file.
3. Check the checksum. Run this in the folder with both files:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   On macOS, use `shasum -a 256 -c --ignore-missing SHA256SUMS`.
4. Extract it and copy the binary to a folder on your `PATH`:

   ```sh
   tar xzf saiife-0.1.0-x86_64-unknown-linux-musl.tar.gz
   mkdir -p ~/.local/bin
   cp saiife-0.1.0-x86_64-unknown-linux-musl/saiife ~/.local/bin/
   ```

## Supported platforms

| Platform | Target |
|---|---|
| Linux, Intel/AMD 64-bit | `x86_64-unknown-linux-musl` |
| Linux, ARM 64-bit | `aarch64-unknown-linux-musl` |
| macOS, Intel | `x86_64-apple-darwin` |
| macOS, Apple silicon | `aarch64-apple-darwin` |

Windows is not supported.

## Build from source

You need Rust installed. From a clone of the repository:

```sh
cargo install --path crates/cli
```

This puts `saiife` in `~/.cargo/bin`.

## Uninstall

1. In each project where you ran `saiife init`, run `saiife init --off`.
   This removes the hooks from your agent settings.
2. Delete the binary, for example `rm ~/.local/bin/saiife`.
3. Optional: delete saiife's data. There are two folders.
   - The data folder holds the integrity records. If `SAIIFE_DATA_DIR` is set to an
     absolute path, that folder is used. Otherwise the default is:
     - Linux: `~/.local/share/saiife` (or `$XDG_DATA_HOME/saiife` if that is set)
     - macOS: `~/Library/Application Support/saiife`
   - The audit log has its own setting. If `SAIIFE_AUDIT_DIR` is set to an absolute
     path, that folder is used. Otherwise the default is:
     - Linux: `~/.local/share/saiife/audit` (or `$XDG_DATA_HOME/saiife/audit`)
     - macOS: `~/Library/Application Support/saiife/audit`

     `SAIIFE_DATA_DIR` does not move the audit log. If you set only `SAIIFE_DATA_DIR`,
     the log stays at the default path.

   The log is your record of what the agents did. Keep it if you may need it.
4. Optional: delete the `.saiife` folder in each project.

## Locked mode (Linux)

In developer mode (everything above) the hooks run as your user, so an agent
running as your user can switch them off. Locked mode moves the hooks, the
policy and the audit log out of the agent user's reach: root installs them,
and a daemon (`saiifed`, its own system user) writes the audit log.

### Supported systems

Ubuntu 22.04 or later, Debian 12 or later, and RHEL 9 or later (also Rocky
and Alma 9+), each with systemd running. Install refuses anything else
(Alpine, containers, no systemd) with one line:
`saiife: locked mode is not supported here: <why>. Developer mode works as before.`
macOS gets locked mode in v2.1.

### Install

```sh
sudo saiife system install --agents claude,codex,gemini
```

- `--agents` defaults to all three. Install only adds managed hooks; to
  remove one, uninstall.
- `--config <file>` installs your system config (it must say
  `locked = true`). Without it, install keeps the current
  `/etc/saiife/config.toml` or writes a commented default.
- `--approvers <list>` sets the approvers in a new default config (user
  names, or `group:<name>`).
- `--non-interactive` for scripts and configuration tools.

Install creates the `saiife` user and the `saiife` and `saiife-audit`
groups, copies the binary to `/opt/saiife/bin/saiife`, writes `/etc/saiife`
(config, `policy.d`, the vault key, `installed.toml`), the
`saiifed.service` unit and the managed hook files
(`/etc/claude-code/managed-settings.d/50-saiife.json`,
`/etc/codex/requirements.toml`, `/etc/gemini-cli/settings.json`), starts the
daemon, then runs `saiife doctor` and prints its report. Running it again
changes only what differs.

Exit codes: 0 installed, 1 installed but `doctor` found a failure (fix it
before you rely on the lock), 2 install error or unsupported system.

The managed hooks fail closed: if the daemon is down, the policy is invalid
or the guard crashes, every agent tool call is denied. Project hooks from
`saiife init` go quiet for agents that have a managed hook. In a project,
`saiife init` then writes only `.saiife/config.toml` (packs can be added,
never removed), and `saiife init --off` removes leftover project hooks and
keeps the config.

### Check it

```sh
sudo saiife doctor          # every check; --json for tools
saiife doctor               # as an agent user: your own account
saiife status               # in a project: the Locked mode block first
```

`doctor` exits 0 when everything passes, 1 on a warning and 2 on a failure.
`status` exits 1 when the daemon does not answer, the policy is invalid or
an installed file changed.

### Lock labels

How well a managed hook holds depends on the agent. The labels come from the
live lock check (`docs/lock-check.md`); `doctor` and `status` show them.

| Agent | Label |
|---|---|
| Claude Code | lockable |
| Codex | unverified (managed hook installed; `doctor` warns) |
| Gemini CLI | unverified (managed hook installed; `doctor` warns) |

### Uninstall

```sh
sudo saiife system uninstall          # keeps config, vault key, state, audit, users
sudo saiife system uninstall --purge  # removes everything install made
```

Uninstall removes exactly what `installed.toml` lists. By default it keeps
`/etc/saiife/config.toml`, the vault key, `/var/lib/saiife`,
`/var/log/saiife` and the users and groups (`--keep-audit` says the same
explicitly). `--purge` also removes the state, the audit log, the config and
vault key install wrote (never an admin's own) and the users and groups.

## Network use

saiife makes no network calls. Only `install.sh` downloads files, and only when you run it.
