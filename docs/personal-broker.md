# Personal broker

The personal broker is `saiife daemon --user`: a daemon that runs as you, on
your own machine, and holds your connector credentials in the OS keychain. It
is for trying connectors on your own machine; **not a security boundary**.
Approvals in this mode allow any approval from the same user. This is a
workflow aid, not a control. If you need a boundary, use locked mode (see
[Threat coverage](threats.md)).

The wording rule (the agent never holds a credential for a brokered service;
it holds its own model-provider login unless you run a local model) is a
locked-mode claim. In this mode it is not guaranteed, because an agent
running as the same user can reach the key; that is a workflow aid, not a
control.

It runs on Linux and macOS (v2.1). On Linux the key is in the Secret
Service; on macOS it is in your login Keychain ([macOS](#macos)).

## Set up

```
saiife daemon --user
```

This creates a minimal config at `$XDG_CONFIG_HOME/saiife/broker/config.toml`
when there is none (mode 0600). `$XDG_RUNTIME_DIR` must be set, absolute, a
real directory (not a symlink), owned by you and mode 0700; otherwise the
start is refused. On macOS, where nothing sets `XDG_RUNTIME_DIR`, the
broker uses `~/Library/Caches/saiife` instead (see [macOS](#macos)).

To start it at login, print the unit and install it yourself. saiife writes
no unit file and runs no service manager:

```
saiife daemon --user --print-unit systemd > ~/.config/systemd/user/saiife-broker.service
systemctl --user daemon-reload
systemctl --user enable --now saiife-broker
```

The systemd user manager does not read your shell profile. If you set
`XDG_CONFIG_HOME`, `XDG_STATE_HOME` or `XDG_DATA_HOME` there, the broker
started by the unit uses the defaults (`~/.config`, `~/.local/state`,
`~/.local/share`) while your shell's `saiife` uses your values, and the two
look at different files. Give both the same environment, either for every
login in `~/.config/environment.d/*.conf`:

```
XDG_CONFIG_HOME=/home/you/.cfg
XDG_STATE_HOME=/home/you/.state
```

or for the running manager only, before the `enable --now` above:

```
systemctl --user import-environment XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME
```

When they still differ, `saiife connect` warns ("the personal broker reads
…, but this shell resolves …") and writes the policy file where the broker
reads it, which the broker names in its `status` answer. `saiife secret`
and `saiife api` go through the socket, so they are not affected.
`saiife audit --broker` reads the audit dir itself, so it needs the same
`XDG_DATA_HOME` as the broker.

On macOS, `saiife daemon --user --print-unit launchd` prints a launchd
agent plist (label `com.saiife.broker`). Save it as
`~/Library/LaunchAgents/com.saiife.broker.plist` and load it yourself, for
example with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.saiife.broker.plist`.

`--user` refuses `--config`, `--state-dir` and `--credentials-dir`: the
paths below are fixed. A host with `/etc/saiife/installed.toml` is a locked
host, and `--user` refuses there.

## Where things live

| What | Path |
| --- | --- |
| Sockets (`saiife.sock`, `gateway.sock`, 0600) | `$XDG_RUNTIME_DIR/saiife/` (0700); on macOS without `XDG_RUNTIME_DIR`, `~/Library/Caches/saiife/run/` |
| Config, plus `policy.d/`, `connectors/` and `ca/` | `$XDG_CONFIG_HOME/saiife/broker/config.toml` (default `~/.config`) |
| State: vault, approvals, grants, tokens, lockdown | `$XDG_STATE_HOME/saiife/broker/` (default `~/.local/state`, 0700) |
| Audit | `$XDG_DATA_HOME/saiife/broker/audit/` (default `~/.local/share`) |

Relative `XDG_*` values are ignored. The audit is kept apart from the
developer hook's own audit.

One broker runs per state directory (an exclusive `flock` on `broker.lock`).
The lock is per state dir, not per user; two brokers with different
`XDG_STATE_HOME` would share the one keychain item, so run one per user.

## Using it

`saiife connect`, `saiife secret`, `saiife api` and `saiife approve` work as
in locked mode, and reach the personal broker when this host is not locked.
A locked host always wins: with `/etc/saiife/config.toml` set to
`locked = true` (or `--config` given), these commands go to the system daemon
and never fall back to the personal broker.

- `saiife secret add <name>` stores a secret. `saiife secret import` is
  refused in this mode (`personal broker: use secret add`): moving plaintext
  out of reach of the agent protects nothing when the key is readable by the
  same user.
- `saiife audit --broker` reads the broker's audit, and
  `saiife audit verify --broker` checks it.
- `saiife env use` (spec 6.11) comes in a later release.
- Your own user is the admin and the approver. A same-user approval needs no
  re-authentication.
- Project overlays may `allow`, as in developer mode.

What differs from locked mode:

- A reload (SIGHUP or `saiife policy reload`) of a config with
  `locked = true` is rejected.
- `[gateway] tcp` is ignored, with a warning. `[daemon]`, `[admin]` and
  `[audit] dir` are ignored too (one warning each).
- With no `[[scope]]`, an implicit scope `personal` lists every configured
  service for you.
- The audit chain is unsigned: there is no signing key, because "a key in the
  user's own home proves nothing". `audit.rotate_key` is refused, and
  `saiife audit verify --broker` labels the result "personal broker: ...".
  Records carry `mode: personal`.
- Peers with another uid, root included, are closed before any answer.

## macOS

- **Runtime dir.** When `XDG_RUNTIME_DIR` is unset, the sockets are in
  `~/Library/Caches/saiife/run/`, and the broker creates
  `~/Library/Caches/saiife` (0700) when it is missing. A set, absolute
  `XDG_RUNTIME_DIR` wins, as on Linux, with the same owner and mode checks.
- **Cache purges.** macOS or a cleaning tool may empty `~/Library/Caches`.
  The broker's sockets go with it, and clients can no longer reach the
  broker. Restart the broker to get them back.
- **Socket path length.** macOS binds a socket path of at most 103 bytes.
  When `gateway.sock`'s path is longer (a long home path), the start is
  refused with `the personal broker's socket path is too long for macOS (<n>
  bytes); set XDG_RUNTIME_DIR to a shorter dir`.
- **Keychain.** The key is a generic password in your login Keychain
  (service `saiife`, account `vault-key`). saiife creates the item, so its
  access list names the saiife binary; another program of yours that reads
  it gets a prompt you may click through.
- The config, state and audit paths are the XDG ones in the table above
  (`~/.config`, `~/.local/state`, `~/.local/share` by default), on macOS too.

## What protects the key, and what does not

One keychain item (service `saiife`, account `vault-key`, label "saiife
personal broker: vault key") holds a 32-byte key. The secrets stay in
`<state>/vault/vault.bin`, sealed under that key. On Linux the item is in the
Secret Service (GNOME Keyring or KWallet); on macOS it is in the login
Keychain.

Any process of the same user can read these on Linux, and on macOS after one
click the user may give. For example, a script running as you can run
`secret-tool lookup application saiife saiife-item vault-key` and then decrypt
`vault.bin`.

What the broker does:

- keeps the key only in zeroed memory, and makes the daemon non-dumpable
  (blocks same-user `ptrace` and `/proc/<pid>/mem`);
- runs the guard rules `core.self` and `core.secrets`, which deny the obvious
  readers and stoppers (`secret-tool lookup ... saiife`,
  `systemctl --user stop saiife-broker`, writes to the broker's config and
  unit).

What it does not stop:

- A same-user script that calls the Secret Service directly (for example with
  `secretstorage`), or `busctl` calls such as `StopUnit`.
- The agent stopping the broker, then binding its own `saiife.sock` to capture
  the next `saiife secret add` value.
- The agent pointing `XDG_RUNTIME_DIR` at a directory it controls for your
  next command. The client checks owners, and that is the same uid.
- The agent writing under `$XDG_STATE_HOME` or `$XDG_DATA_HOME` when they
  point away from the default places. The guard rules are a mistake layer, not
  a wall: they do not protect against the same uid.
- A same-uid agent rewriting or deleting the unsigned audit chain.
- Anyone with root.

## When the keychain is unavailable

With no session bus, no Secret Service or a dismissed unlock prompt, the
daemon still starts and serves its audit. The vault is unavailable, a
`vault_unavailable` record gives the reason, and connector calls are denied.
Look with `saiife audit --broker`.

## When the key is lost

If the keychain lost the key but `vault.bin` is still there (a new keyring, a
cleared item, another desktop session), the broker never makes a new key over
the old vault. The vault stays unavailable, the file is kept untouched, and
the reason names it. Either restore the keyring item, or remove
`<state>/vault/vault.bin` and add the secrets again.
