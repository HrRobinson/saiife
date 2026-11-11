# Touch approvals

Some approvals can ask for more than a yes. A touch is a signature from a
FIDO2 security key that saiife's daemon checks and records. This page says what
counts, how to set a key up, how to approve with it, and where it stops.

Touch is optional. Nothing asks for it until a policy marks an action as
needing one ([Touch marks](#4-touch-marks)).

The commands below are specified by plan 27 and land with its CLI tasks.
`saiife doctor` already has the key check ([Setup](#2-setup)).

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

When no key is reachable the request is refused (`touch_unavailable`). saiife
never falls back to a password.

## 2. Setup

1. Set a PIN on the key (with the vendor's tool, for example `ykman fido access
   change-pin`).
2. Enrol it at the machine, as root or as a local approver:

   ```
   saiife touch enrol --label desk-key
   ```

   The first device needs host access. Each later device needs a touch from one
   already enrolled.
3. Enrol a second device the same way (`saiife touch enrol --label spare-key`).
   Two devices are recommended: with one, losing it leaves you at the recovery
   path below.

Other commands:

- `saiife touch ls [--json] [--all]` lists the enrolled devices;
- `saiife touch rm <id-prefix> [--host]` removes one;
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

`saiife approve <id>` asks for the touch itself when the request needs one:

```
saiife: touch needed (land); code 123456; check that the same code shows wherever you started this
PIN for your security key:
touch your key now
```

- The short code is derived from the challenge. Check that it matches the one
  shown where the request was started.
- The PIN is typed without echo. It is not logged, not sent to the daemon and
  not kept.
- Each prompt waits 120 seconds. After that the CLI prints `no touch within
  120 s` and exits 5, and the request stays pending.
- The challenge the daemon issued lives 5 minutes.
- One key at a time: with none plugged in the CLI says so, and with more than
  one it asks you to leave only the one to use.
- A timeout, an error or the wrong device all mean deny. The request is not
  approved by any other means.

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
stay pending or time out. As root on the host:

```
saiife touch rm <id-prefix> --host
```

removes an enrolled device without a touch. The removal is recorded in the
audit log, and then you enrol a new device at the machine. Root on the host can
do anything; the record makes it visible, not impossible.

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

`saiife touch ...` and an `approve` that needs a touch then exit 5.

- The macOS and Windows release builds carry key support.
- The Linux release packages are static, and the main `saiife` binary stays
  static. Key support for them is planned through a small dynamically linked
  helper binary shipped in the Linux packages. It is not built yet.
- A Linux build from source has it with `cargo build --features fido-hid`. The
  build needs the libudev development files and `pkg-config`.
