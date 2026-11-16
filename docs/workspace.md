# Workspace (localhost)

The Workspace is a web page that shows your boxes and lets you steer them from
a browser. Today it runs on your own machine, at `http://localhost:47810`. When
the hub ships, the same page will also be served from app.saiife.com.

Boxes run on Linux only and are not in a release yet. Where the daemon runs no
boxes, the page has nothing to show, except on the demo build (see
[Try it before boxes ship](#try-it-before-boxes-ship)).

## Start it

Run the link in one terminal:

```
saiife workspace serve
```

It listens on `127.0.0.1` only, port 47810. Use `--port` to change it.

Pair a browser from another terminal:

```
saiife workspace pair --local
```

This shows a QR code and a link. Open the link in the browser you want to
pair. Use `--port` if you changed the port. `--label` is a note on the offer,
kept in its audit record. The name the device list shows is the one typed in
the page when you pair.

## Pairing

- The page shows a short code. The terminal shows the same code. Check that
  they match, then accept in the terminal.
- The secret is in the part of the link after `#`. The browser never sends that
  part to a server. The page removes it from the address bar at once.
- A pairing offer works once. It expires after 5 minutes.
- Accepting may ask for your password, as other commands that grant power do.

The browser makes a key that it cannot export (WebCrypto, kept in IndexedDB).
Every action is signed with that key. Clearing the site data in the browser
deletes the key, so the browser is no longer paired. The device stays in the
list until you revoke it.

## Devices

```
saiife workspace devices
saiife workspace revoke <device id>
```

`devices` lists paired browsers with their ids (`d-...`). `revoke` removes
one. Revoking is done on the machine, never from the page.

When the daemon no longer knows a browser (for example, it was revoked), the
page forgets its key and shows the pair screen:
"This browser is no longer paired." To pair it again, run
`saiife workspace pair --local` on the machine and open the link it prints.

## What the page does

| Screen | What you can do |
|---|---|
| Overview | See boxes, load and free slots. Reorder queued boxes. "Lockdown on" (`lockdown.on`) asks "Stop every agent on this machine?" first. The page asks again every 3 s while the tab is visible. It does not use push. |
| Review | Read the diff and the test result of a finished box. Approve it with a touch (lands it), send it back with a comment (Revise, a touch), or reject it (discards the box). |
| Spawn | Start a box from a template. A template with secrets or external egress asks for a touch. |
| Inbox | See what waits for you: a box's land (opens its Review screen) and approval requests you may decide (Approve with a touch). The page asks again every 5 s while the tab is visible. |
| Steer | Pause or stop a box. Sending a message, Revise and Resume need a touch (one touch covers a 10-minute window, see [The steer window](#the-steer-window)). The box's terminal is shown read only, updated at most once a second while the tab is visible. |
| Pair | Pair this browser. |

The diff shows the first 2000 lines. A file cut by that limit says how many of
its lines are not shown. If the daemon cut the diff, the page says so. File
names and text from a box are shown as plain text. Control and direction
characters appear as visible escapes.

The terminal pane is plain text with no buttons, links or inputs. The machine
has already applied the terminal's escapes; anything left that looks like one
(a clipboard write, a link, a drawn "Approve" button) is shown as text and does
nothing. When the box finishes, the pane says "The terminal has ended".

## What needs a touch

Anything that only takes power away is safe from a signed browser. Anything
that gives power needs a touch on a paired passkey.

| Level | Actions |
|---|---|
| Signed browser key | `box.overview`, `box.list`, `box.diff`, `box.inbox`, `box.templates`, `box.term.read`, `approval.list`; `box.pause`, `box.stop`, `box.reorder`, `box.discard`, `approval.reject`; `lockdown.on`; `box.spawn` with a template that has no secrets and no egress |
| Needs a touch | `box.land`, `box.steer`, `box.revise`, `box.resume`, `approval.approve`; `box.spawn` with a template that has secrets or egress |
| Not from the browser | `box.push`, `box.pr` (see [Why push stays on the machine](#why-push-stays-on-the-machine)) |
| Machine only | policy, config, vault, connectors, egress; enrolling or removing devices (including pairing and revoking); `lockdown.off`; raising caps; uninstall; anything about the audit |

A touch is a WebAuthn assertion from a passkey enrolled for this device. It
binds the exact action the page showed: the daemon makes the challenge from
the action record (what, which box, expiry), and an assertion for one action
or one box is refused for another (`touch_mismatch`). A challenge works once
and is valid for 5 minutes. A browser can hold at most 4 challenges that are
not yet used or expired, and a user at most 8 across all their browsers and
the machine's own touches (lands, pushes, approvals). One more is refused
with `busy`. The record's reason says which limit it hit: "too many touches
in progress on this device" for the browser's 4, "too many touches in
progress" for the user's 8. The prompt times out after 120 seconds. A
timeout, an error or the wrong passkey all deny: the page says "Not approved"
and sends nothing. There is never a password fallback.

The page shows a 6-digit short code before the passkey dialog opens. The
same code is in the inbox, and in the optional `box_waiting` notification,
so you can check that the prompt is the one you meant to answer. That
notification carries the box and the code and no link. It is sent once per
finished run of a box, when the daemon first offers that run's result in the
inbox. A land request expires after 5 minutes and the inbox offers it again
under a new request id (and a new code); that sends no second notification.
When the box is revised and finishes again, the new result sends one more.
See [notifications](notifications.md). If this browser has no passkey, the page
says "Needs a touch on a paired passkey" and shows the machine command
instead.

- **Land.** The touch is for one pending land of one box. Landing is a
  pending action the daemon made; the browser answers it from the box's
  Review screen, next to the diff.
- **Spawn.** A template with secrets asks for the secret-sensitive touch; one
  with external egress asks for the egress touch. A template with neither
  needs no touch.
- **Approvals.** `approval.approve` needs a touch. `approval.reject` and
  `approval.list` need only the signed browser key. `[approval] same_user`
  still applies: with `"deny"` (the default) the requester cannot approve
  their own request, from the page either. With `"reauth"` the touch replaces
  the polkit password prompt, because it already proves presence and user
  verification. See [approvals](approvals.md).

## Passkeys

A passkey is made only while you pair. The browser asks for the new passkey
first (Face ID, a fingerprint or a PIN), and the browser's own device key signs
it into the pairing request, so a relay on the way cannot swap in its own. The
machine stores the passkey only when you accept the pairing there. A pairing without a passkey works for the signed actions, but nothing in
the touch row will work for that browser.

User verification is required for every touch: Face ID, a fingerprint or the
key's PIN. A passkey or key that does not verify the user is refused
(`touch_failed`). The page says "Needs Face ID, fingerprint or PIN".

Whether this browser has a passkey is the machine's answer, not the page's:
after you accept the pairing, the page asks the daemon which passkeys it holds
for this browser. If there are none, the page says that touches are not
available on this browser.

A passkey belongs to one origin. A touch made for another origin (a different
host or port) is refused.

## `[workspace] origins`

```toml
[workspace]
origins = ["http://localhost:47810"]
```

The list is in the machine's config, like all config. A touch is accepted
only when the page's origin is in the list. The WebAuthn RP id is the host of
the origin (`localhost` for the default), taken from this list and never from
the browser. The default is the page `saiife workspace serve` shows on port
47810. If you use `serve --port N`, add `http://localhost:N`. To use a phone
over Tailscale, add the https origin the phone opens, for example
`https://box.tail1234.ts.net`. Each entry is `http://localhost:<port>` or
`https://<host>[:port]`; nothing else is accepted. A passkey made at one
origin works only there.

## The steer window

Steer sends a message to a running box, Revise sends a comment to a finished
one, and Resume carries on a paused one (it sends no text). The touch does not
bind the text; it opens a window. One touch opens a window of 600 seconds (10
minutes) for that browser and that box. Inside the window, further steers,
revises and resumes of the same box need no touch. The window is per browser
and per box: another browser, or another box, asks for its own touch. It
closes at once when you revoke the browser, and it ends after 600 seconds. A
frame covered by a window is recorded with `window: true`. The window opens
once the touch is verified, even if the action itself then fails.

## Why push stays on the machine

`box.push` and `box.pr` send a box's work to a remote. They are not offered
to the browser at all, because a compromised page or hub must not be able to
send code out. Pushing is done on the machine, with the CLI.

The browser can land a box into the local repository (`box.land`) and nothing
more.

Machine-only actions are not offered in the page at all. A frame that asks for
one is refused.

## The audit

Every change from the page is recorded by the daemon: reorder, stop, pause,
discard, spawn, lockdown on and so on. Each record has the device id and
`via: "local"`. A frame that needed a touch also carries a `touch` object: the
credential, `uv`, the challenge and the signature, with `via: "web"`, so
`saiife audit verify` and an auditor can check it. A frame covered by a
steer window has `window: true` instead. A frame refused after its
signature checked out is recorded with the rule that refused it. A frame from
an unknown or revoked device, or one with a bad signature, is not recorded.
Successful reads (overview, diff, inbox) are not recorded. A read the daemon
refuses is recorded.

## Try it before boxes ship

The daemon has a `fake-boxes` Cargo feature. With it, and with
`SAIIFE_WORKSPACE_FAKE_BOXES=1` in the daemon's environment, the Workspace
shows four demo boxes, including a finished one whose diff holds hostile file
names. It is for trying the page. It is a test build only and is never in a
release.

```
SAIIFE_WORKSPACE_FAKE_BOXES=1 cargo run -p saiife-daemon --features fake-boxes
```

## Honest limits

- The page is JavaScript served to your browser. If the thing that serves it
  is compromised (on app.saiife.com, the hub front end), it can mislead what
  you see. The signature still binds the real action, and the daemon accepts
  only actions it created. A native app or pinned build would close this. It
  is not in v3.0. On localhost the page comes from `saiife-link` on your own
  machine.
- A synced passkey means any of your synced devices, not one phone. A touch
  proves presence. Proving who needs user verification (PIN or biometrics).
- Root on the machine can still do anything. The audit makes that visible, not
  impossible.
- Clearing site data unpairs the browser but does not revoke it. Revoke it
  with `saiife workspace revoke`.
