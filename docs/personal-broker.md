# Personal broker

The personal broker is `saiife daemon --user`: a daemon that runs as you, on
your own machine, and holds your connector credentials in the OS keychain. It
is for trying connectors on your own machine; **not a security boundary**.
Approvals in this mode allow any approval from the same user. This is a
workflow aid, not a control. If you need a boundary, use locked mode (see
[Threat coverage](threats.md)).

The wording rule applies here as everywhere: the agent never holds a
credential for a brokered service; it holds its own model-provider login
unless you run a local model.

Linux only in this version. On macOS `saiife daemon --user` refuses to start
until the daemon is ported (v2.1). The macOS Keychain backend is built, but
nothing runs it yet.

## Set up

```
saiife daemon --user
```

This creates a minimal config at `$XDG_CONFIG_HOME/saiife/broker/config.toml`
when there is none (mode 0600). `$XDG_RUNTIME_DIR` must be set, absolute, a
real directory (not a symlink), owned by you and mode 0700; otherwise the
start is refused.

To start it at login, print the unit and install it yourself. saiife writes
no unit file and runs no service manager:

```
saiife daemon --user --print-unit systemd > ~/.config/systemd/user/saiife-broker.service
systemctl --user daemon-reload
systemctl --user enable --now saiife-broker
```

`saiife daemon --user --print-unit launchd` prints a launchd plist. It is for
after the v2.1 daemon port; it does not work on a Mac today.

`--user` refuses `--config`, `--state-dir` and `--credentials-dir`: the
paths below are fixed. A host with `/etc/saiife/installed.toml` is a locked
host, and `--user` refuses there.

## Where things live

| What | Path |
| --- | --- |
| Sockets (`saiife.sock`, `gateway.sock`, 0600) | `$XDG_RUNTIME_DIR/saiife/` (0700) |
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
- `saiife env use` (spec 6.11) arrives with the connector waves in plan 14.
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

## What protects the key, and what does not

One keychain item (service `saiife`, account `vault-key`, label "saiife
personal broker: vault key") holds a 32-byte key. The secrets stay in
`<state>/vault/vault.bin`, sealed under that key. On Linux the item is in the
Secret Service (GNOME Keyring or KWallet).

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
