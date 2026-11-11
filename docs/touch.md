# Touch approvals

Some approvals can ask for more than a yes. A touch is a signature from a
FIDO2 security key that saiife's daemon checks and records. This page says what
counts, how to set a key up, how to approve with it, and where it stops.

Touch is optional. Nothing asks for it until a policy marks an action as
needing one ([Touch marks](#4-touch-marks)).

## 1. What counts as a touch

Only an answer that produces a signature the daemon (and later an auditor) can
verify counts:

- a FIDO2 hardware key (a YubiKey, or a YubiKey Bio for a fingerprint), used
  through the CLI over CTAP;
- later: a WebAuthn passkey in the Workspace, Windows Hello, and a macOS Secure
  Enclave key gated by biometry.

A PIN-only answer is not a touch, and neither is a fingerprint read by fprintd,
a polkit prompt or a PAM module. Those say yes or no and leave no proof. The
polkit re-authentication stays as it is for same-user approvals.

saiife never falls back to a password. Two cases differ:

- The CLI gets no touch: no key is plugged in, the prompt times out, or the key
  gives an error (a wrong PIN, a device not enrolled for you). `saiife approve`
  then sends no decision at all. It exits 5 when no key answers and 2 when the
  key refuses. The request stays pending and nothing is approved; it can still
  be approved later with a touch, be rejected, or expire.
- A decision reaches the daemon without a touch (a client that sends none),
  or the approver has no device enrolled. The daemon refuses it
  (`touch_unavailable`, recorded in the audit), and the request stays pending.

## 2. Setup

1. Set a PIN on the key (with the vendor's tool, for example `ykman fido access
   change-pin`).
2. Enrol it at the machine, as root, an `[admin] groups` member or a local
   approver (in personal mode: you):

   ```
   saiife touch enrol --label desk-key
   ```

   The first device needs host access. Each later device needs a touch from one
   already enrolled: the CLI asks you to touch the new key twice, then to unplug
   it, plug in an enrolled one and press Enter, and touch that one.
3. Enrol a second device the same way (`saiife touch enrol --label spare-key`).
   Two devices are recommended: with one, losing it leaves you at the recovery
   path below.

Other commands:

- `saiife touch ls [--json] [--all]` lists your enrolled devices (`--all`:
  every device on the machine, for root or an admin);
- `saiife touch rm <id-prefix>` removes one of yours, with a touch of one of
  them; the prefix is at least 8 characters of the id `ls` shows. `--host` is
  root's recovery in locked mode ([Recovery](#5-recovery));
- `saiife touch test` asks for a touch and checks it, without approving
  anything.

Enrolment and removal are signed audit records.

### Access to the key on Linux

Reading the key needs access to its `hidraw` node. On Arch, and on any system
with systemd 248 or newer, the logged-in user at the machine gets it from the
`uaccess` tag, and nothing needs doing. An SSH session gets no access.

On other distributions, install the libfido2 udev rules (`70-u2f.rules`, from the
`libfido2` or `libu2f-udev` package). That is a step for the machine's owner;
saiife never installs it.

`saiife doctor` reports the state in its `touch-key` check: Info when no FIDO
key is plugged in, Pass when the node is usable by you, and Warn when it is
plugged in but you cannot use it. It only tests access and never opens the
node. It is never a failure.

## 3. Approving with a touch

`saiife approvals show <id>` names the class of a request that needs a touch:

```
  touch:     deploy (your enrolled key, and its PIN)
```

`saiife approve <id>` asks for the touch itself when the request needs one. It
prints what is approved first, then the class and a short code, then asks:

```
saiife: approving request #12: connector erp deploy.run
saiife: touch needed (deploy); code 123456; check that the same code shows wherever you started this
PIN for your security key:
saiife: touch your key now
```

- The short code is derived from the challenge. Check that it matches the one
  shown where the request was started.
- The PIN is asked for when the class needs user verification (`land`,
  `deploy` and `secret:sensitive`). It is typed without echo. It is not logged,
  not sent to the daemon and not kept.
- Each prompt waits 120 seconds. After that the CLI prints `no touch within
  120 s` and exits 5, and the request stays pending.
- The challenge the daemon issued lives 5 minutes.
- One key at a time: with none plugged in the CLI says so, and with more than
  one it asks you to leave only the one to use.
- A timeout, an error or the wrong device means no approval: the CLI sends no
  decision and the request stays pending (exit 5 when no key answers, 2 when
  the key refuses). It is not approved by any other means.
- In locked mode, a same-user approval still asks for its re-authentication
  after the touch, as well as the touch, never instead.
- `saiife reject <id>` needs no touch.

The daemon checks the signature against the enrolled key, the challenge, the
user-presence and user-verification flags, the expiry (and burns the nonce), and
that the signature counter does not go backwards.

## 4. Touch marks

Which actions need a touch is set by marks in policy: for example landing a
box's diff, a push to a protected branch, a secret marked sensitive, or a call
to a host marked as a real system. See [Approvals](approvals.md) for how
approvals work in general. Nothing is marked unless you mark it.

## 5. Recovery

If every device is lost, a touch cannot be given. Pending requests that need one
stay pending until they are rejected or expire.

**Locked mode.** As root on the host:

```
saiife touch ls --all
saiife touch rm <id-prefix> --host
```

removes an enrolled device without a touch. The removal is recorded in the
audit log, and then you enrol a new device at the machine. Root on the host can
do anything; the record makes it visible, not impossible.

**Personal mode.** There is no `--host` removal. The device list is your own
file: stop the personal broker, delete
`$XDG_STATE_HOME/saiife/broker/state/touch/credentials.json` (by default
`~/.local/state/saiife/broker/state/touch/credentials.json`; on Windows
`%LOCALAPPDATA%\saiife\personal\state\state\touch\credentials.json`), start
the broker again and enrol a new device. Nothing records the deletion: personal
mode is a workflow aid, not a security boundary
([personal-broker.md](personal-broker.md)).

## 6. Limits

- Attestation is not checked. Any FIDO2 device can be enrolled, by someone with
  access to the host. saiife does not tell a genuine YubiKey from any other
  authenticator.
- A synced passkey means "any of your synced devices", not one phone. User
  presence proves a touch happened, and user verification is needed to prove who
  gave it.
- Root on the host can still do anything. The audit and its forwarding make that
  visible, not impossible.

## 7. Builds

Key support is a build feature. A build without it refuses with:

```
this saiife build has no FIDO2 key support (a static Linux build); see docs/touch.md
```

`saiife touch enrol`, `saiife touch test`, `saiife touch rm` (without
`--host`) and an `approve` that needs a touch then exit 5. `saiife touch ls`
still lists the devices and prints the line as a note.

- The macOS and Windows release builds carry key support.
- The Linux release packages are static, and the main `saiife` binary stays
  static. Key support for them is planned through a small dynamically linked
  helper binary shipped in the Linux packages. It is not built yet.
- A Linux build from source has it with `cargo build --features fido-hid`. The
  build needs the libudev development files and `pkg-config`.
