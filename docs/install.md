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
For macOS, see [Locked mode (macOS)](#locked-mode-macos).

### Install

Install the **static release binary** (the `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl` tarball) and run it from a path only root can
change. Do not run `sudo "$(command -v saiife)" system install` on a binary
in your home: sudo's `secure_path` does not search `~/.local/bin`, and a
file your user owns could be swapped before root runs it. Download and
check the tarball as described in [Manual install](#manual-install), then:

```sh
sudo install -m 0755 -o root -g root ./saiife /usr/local/bin/saiife
sudo /usr/local/bin/saiife system install --agents claude,codex,gemini
```

(or download and extract the tarball as root.) Install copies the binary it
runs to `/opt/saiife/bin/saiife`.

Install refuses to write below a directory that is not root's or that
group or others can write (sticky directories excepted): another user
could swap what install puts there. It names the directory
(`saiife: install failed at check: /opt: mode 0777 is writable by group or
others`). Check the owner and mode, and if nothing on the machine needs
it writable, fix it before installing, for example `sudo chmod go-w /opt`.

**Why only the static release build (spec §9.2 A4).** The managed hooks run
`/opt/saiife/bin/saiife` as the agent user, in an environment the agent can
shape: Claude Code's settings `env`, for one, is set by files the agent can
write. A dynamically linked binary loads whatever `LD_PRELOAD` names before
`main`, so an agent could persist `LD_PRELOAD` there and run its own code
inside the hook that judges it. A build with debug assertions (`cargo build`
without `--release`) has a test seam (`SAIIFE_EVAL_FAULT`) that can hang the
guard past an agent's hook timeout; Codex and Gemini CLI then fail open.
It also has `SAIIFE_TEST_CLAUDE_MCP_DROPIN`, which can point the hook at
another Claude Code MCP drop-in and so grant `Brokered` to a `saiife`
server whose command is not pinned, and (macOS) `SAIIFE_TEST_ALLOW_SIP_OFF=1`,
which lets install and `doctor` go on without System Integrity Protection
(install warns, `doctor` reports `system.sip` as a warning; see
[Locked mode (macOS)](#supported-systems-macos)). A release build never
reads either. So
`system install` refuses (exit 2) a binary that is dynamically linked (an
ELF interpreter or a needed shared library), has debug assertions on, or has
no saiife build marker, and `saiife doctor` fails `files.binary` on a
dynamic binary and warns `test build installed` on a debug-assertions build.
The hidden `--allow-test-build` flag exists for the CI jobs `locked-linux`
and `locked-macos` only; never use it in production.

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
`saiife init` go quiet for an agent only when its managed hook was written
and its lock label holds (lockable, with gaps or with caveats). For Codex and
Gemini CLI (unverified today), and for a managed file whose write did not
finish, the project hook keeps judging and `saiife status` says so. In a project,
`saiife init` then writes only `.saiife/config.toml` (packs can be added,
never removed), and `saiife init --off` removes leftover project hooks and
keeps the config.

Once it runs, you can forward the audit elsewhere
([forwarding](forwarding.md)), give auditors read access ([auditors](auditors.md))
and limit a dedicated agent account's network ([egress](egress.md)).

### Packages (.deb, .rpm)

For many machines, install the `.deb` or `.rpm` from the release page instead.
The package puts the binary in `/usr/libexec/saiife/` and runs
`saiife system install --fleet`, which reads its options from
`/etc/saiife/fleet/`. Removing the package uninstalls locked mode, with a
warning. Check the files with `SHA256SUMS` and `SHA256SUMS.asc` first. See
[Fleet install](fleet.md) for the fleet files, upgrades, removal, Ansible and
Intune.

### Check it

```sh
sudo saiife doctor          # every check; --json for tools
saiife doctor               # as an agent user: your own account
saiife status               # in a project: the Locked mode block first
```

`doctor` exits 0 when everything passes, 1 on a warning and 2 on a failure.
Its sudo check reads `sudo -l` only: rules in doas, polkit (`pkexec`) or
`run0` that give an agent user root are not checked.
`status` exits 1 when the daemon does not answer, the policy is invalid or
an installed file changed.

### Lock labels

How well a managed hook holds depends on the agent and the platform. The
labels come from the live lock check ([lock-check](lock-check.md)); `doctor`
and `status` show them.

| Agent | Linux | macOS |
|---|---|---|
| Claude Code | lockable | unverified |
| Codex | unverified | unverified |
| Gemini CLI | unverified | unverified |

An unverified agent still gets its managed hook, and `doctor` warns. The
macOS labels stay unverified until the lock check has been run in a macOS
VM ([lock-check](lock-check.md#macos-in-a-throwaway-vm)).

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
It removes `/var/lib/saiife` and `/var/log/saiife/audit` relative to open
directory handles from `/`, so a group-writable ancestor (stock Ubuntu's
`/var/log` is `root:syslog 0775`) does not matter; it refuses when a tree is
not owned by root or `saiife`, or its parent directory is not root's or is
writable by others. If `systemctl disable --now saiifed` fails and systemd
does not report the daemon `inactive` or `failed`, `--purge` stops before
it removes anything.

## Locked mode (macOS)

Locked mode on macOS (v2.1) works as on Linux: root installs the hooks, the
policy and a daemon that runs as its own hidden user and writes the audit
log. The commands are the same. This section lists what differs.

### Supported systems (macOS)

macOS 15 (Sequoia) or later, on Apple silicon or Intel. Install refuses an
older macOS with
`saiife: locked mode is not supported here: macOS 14.6 is not supported for locked mode (macOS 15 or later). Developer mode works as before.`

System Integrity Protection must be on. Without it the hardened runtime
does not keep an injected library (`DYLD_INSERT_LIBRARIES`) out of the
managed hook. Install reads `csrutil status` and goes on only when it says,
exactly, `System Integrity Protection status: enabled.`. Disabled,
`unknown`, a custom configuration (even one listing every part enabled) or
an error is refused, exit 2, before anything is changed:

```
saiife: locked mode on macOS needs System Integrity Protection: without it the hardened runtime does not stop library injection (DYLD_INSERT_LIBRARIES). Enable SIP (Recovery: csrutil enable) and run install again.
```

`doctor` fails `system.sip` for the same reason.

### Install (macOS)

Use the release binary for your Mac (the `aarch64-apple-darwin` or
`x86_64-apple-darwin` tarball), checked as described in
[Manual install](#manual-install), and run it from a folder only root can
change. `/usr/local/bin` is not such a folder when Homebrew owns it, so
extract the tarball as root, for example into root's home:

```sh
sudo mkdir -m 0700 /var/root/saiife-install
sudo tar xzf saiife-0.3.0-aarch64-apple-darwin.tar.gz -C /var/root/saiife-install
sudo /var/root/saiife-install/saiife-0.3.0-aarch64-apple-darwin/saiife system install \
  --agents claude,codex,gemini --approvers alice
```

The flags are the ones listed for Linux. Install copies the binary to
`/opt/saiife/bin/saiife` and writes:

| What | Where |
|---|---|
| Daemon user and group | `_saiife`: a hidden local account (`IsHidden = 1`, shell `/usr/bin/false`) with a uid and gid from 200–400, created with `dscl` |
| Audit group | `_saiifeaudit` (auditors, see [auditors](auditors.md)) |
| Config, `policy.d`, `installed.toml` | `/etc/saiife` (which is `/private/etc/saiife`) |
| State | `/var/db/saiife` (0700 `_saiife`) |
| Vault key | `/var/db/saiife/keys/vault.key` (0400 `_saiife`; `installed.toml` says `vault_key = "daemon_file"`) |
| Sockets | `/var/db/saiife-run` (0755 `_saiife`; `[daemon] socket_dir` defaults to it) |
| Audit | `/var/log/saiife/audit` (`_saiife:_saiifeaudit` 2750) |
| Daemon errors (stderr) | `/var/log/saiife/daemon.log` (0640) |
| launchd job | `/Library/LaunchDaemons/com.saiife.saiifed.plist` (root:wheel 0644; `UserName = _saiife`, `KeepAlive`, `RunAtLoad`, `ThrottleInterval = 1`) |
| Authorization right | `com.saiife.approve` (in the authorization database; not used for approvals yet, see below) |
| Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json` and `60-saiife-mcp.json` |
| Codex | `/etc/codex/requirements.toml` |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json` |

Install refuses an existing `_saiife` account that is not hidden, has a
login shell or a uid of 500 or more, or lives in a directory node other
than the local one. It reuses a
hidden local `_saiife` with the shell `/usr/bin/false`. The daemon's socket
dir is `/var/db/saiife-run`, not `/var/run/saiife`: the daemon user cannot
create a dir in `/var/run`, and macOS clears it at boot. The daemon has no
journal on macOS, so when it does not start, read
`/var/log/saiife/daemon.log`.

When `/Library/Managed Preferences/com.anthropic.claudecode.plist` exists,
an MDM profile may also deliver Claude Code's managed settings, and Claude
Code may then ignore saiife's drop-in. Install and `doctor` warn about it.

**Signature (spec §9.2 A4).** On macOS the hooks run a binary that the
agent's environment can reach with `DYLD_INSERT_LIBRARIES`. The hardened
runtime makes macOS ignore it. So `system install` refuses (exit 2) a binary
that is not a thin 64-bit Mach-O, is unsigned, lacks the hardened runtime,
is a build with debug assertions, or carries no saiife build marker. An
ad-hoc signature, or one without a
certificate, only warns: the hardened runtime still holds, but nobody vouches
for who built the file. `doctor` checks the same in `files.binary`.

The release binaries are built that way:

- A tagged release with all six signing secrets in CI is signed with a
  Developer ID and the hardened runtime, and notarized. A bare binary cannot
  be stapled, so Gatekeeper checks the notarization online.
- Any other build (a workflow run, a fork, a tag without the secrets) is
  ad-hoc signed with the hardened runtime and not notarized. The release
  notes then say so ("macOS binaries in this release are ad-hoc signed and
  not notarized"), and install warns.

### Approvals on macOS: a second account

**Same-user approval is off on macOS.** The macOS password or Touch ID prompt
cannot show which request it approves, so an agent running as you could
start an approval of its own request and get you to confirm it. So
`same_user = "reauth"` acts as `"deny"` on macOS. Install still registers
the right, but a new config keeps `same_user = "deny"`, and install always
warns `same-user approval is off on macOS: approvals need a second account`.
`doctor` reports the same line, as a
warning with `re-authentication unavailable: approvals need a second account`
added when the right is missing or weakened.
Approve from a second account that is in `[approval] approvers`, at the Mac
or over SSH (`ssh alice@mac`, then `saiife approve 42`). For the same
reason, on macOS only root and `[admin]` users can lift or narrow
`saiife lockdown`: the approver route needs re-authentication. See
[approvals](approvals.md#macos).

### What else differs on macOS

- **Agent accounts.** An agent user in the `admin` group is a warning in
  `doctor` (`agent user <u> is an admin: sudo needs its password`); a
  NOPASSWD sudo rule for it is still a failure.
- **`core.lock`** also denies `security authorizationdb` writes (`write`,
  `remove`, `merge`) and `dscl` or `dseditgroup` commands that name a
  `_saiife` account, so an agent cannot weaken the right or join the
  daemon's groups through a tool call.
- **`saiife run --secret` and `run --cloud`** work. `DYLD_*` variables are
  removed from the command's environment, as `LD_*` are (on every platform).
  `/etc`, `/var` and `/tmp` are symlinks into `/private` on macOS, and a link
  in `run_allow` never grants its target, so an entry through one is a load
  error with a hint: `run_allow entry /var/x goes through the /var symlink
  on macOS; write /private/var/x instead`.
- **The MCP gateway is Linux only** in this version: `[mcp.<name>]` is a load
  error on macOS. `saiife mcp` (the connector tools) works. See
  [MCP](mcp.md).
- **Process facts.** The daemon reads the peer's uid with `LOCAL_PEERCRED`.
  `LOCAL_PEERPID` gives the pid of the process that last used the socket,
  not strictly the one that connected, so on macOS nothing is granted on a
  pid. The pid and the process names (read with `sysctl(KERN_PROC_PID)`)
  are used for attribution only. Sessions match agents by process name
  alone: a Gemini CLI that runs as `node` gets no session and shares the
  stricter per-uid limits.
- **No egress recipe.** `pf` has no per-uid firewall to rely on; the
  [egress recipe](egress.md) is Linux only.
- **One `unsafe` crate.** `saiife-darwin` makes the one `sysctl` call the
  process facts need. It is the only crate allowed `unsafe`: the workspace
  lint `unsafe_code = "forbid"` and `scripts/check-unsafe.sh` in CI enforce
  that. Known limit: `unsafe` that a dependency's macro expands into is not
  caught.

### Check it (macOS)

```sh
sudo saiife doctor
```

On macOS `doctor` also checks System Integrity Protection (`system.sip`),
the launchd job (the plist install recorded,
and `launchctl print system/com.saiife.saiifed`), the binary's signature,
the authorization right, the `_saiifeaudit` group and the MDM profile. It
skips the Linux-only checks (systemd, polkit, `/proc`, Landlock).

### Uninstall (macOS)

```sh
sudo saiife system uninstall
sudo saiife system uninstall --purge
```

Uninstall stops the job with `launchctl bootout` (and refuses when that
fails while launchd still has the job loaded), removes the authorization
right, and removes what `installed.toml` lists. It keeps `/etc/saiife`,
`/var/db/saiife` (with the vault key), `/var/log/saiife/audit` and the
`_saiife` user and groups. `--purge` also removes those, `/var/db/saiife-run`
and `daemon.log`, and deletes the accounts with `dscl`.

## Network use

saiife makes no network calls. Only `install.sh` downloads files, and only when you run it.
