# Workspace (localhost)

The Workspace is a web page that shows your boxes and lets you steer them from
a browser. Today it runs on your own machine, at `http://localhost:47810`. When
the hub ships, the same page will also be served from app.saiife.com.

Boxes themselves arrive in a later release. Until then the page has nothing to
show, except on the demo build (see [Try it before boxes ship](#try-it-before-boxes-ship)).

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
pair. Use `--label` to name the browser, and `--port` if you changed the port.

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
one. A revoked browser sees "This browser is no longer paired". Revoking is
done on the machine, never from the page.

## What the page does

| Screen | What you can do |
|---|---|
| Overview | See boxes, load and free slots. Reorder queued boxes. "Stop every agent" (`lockdown.on`) asks you to confirm first. The page asks again every 3 s while the tab is visible. It does not use push. |
| Review | Read the diff and the test result of a finished box. Reject it (discards the box). |
| Spawn | Start a box from a template. |
| Inbox | See what waits for you. The page asks again every 5 s while the tab is visible. |
| Steer | Pause or stop a box. Both work. Sending a message and Resume need a touch, so they are refused for now. |
| Pair | Pair this browser. |

The diff shows the first 2000 lines. If the daemon cut the diff, the page says
so. File names and text from a box are shown as plain text. Control and
direction characters appear as visible escapes.

## What needs a touch

Anything that only takes power away is safe from a signed browser. Anything
that gives power needs a touch on a paired passkey.

| Level | Actions |
|---|---|
| Signed browser key | `box.overview`, `box.list`, `box.diff`, `box.inbox`, `box.templates`, `box.term.read`, `approval.list`; `box.pause`, `box.stop`, `box.reorder`, `box.discard`, `approval.reject`; `lockdown.on`; `box.spawn` with a template that has no secrets and no egress |
| Needs a touch | `box.land`, `box.push`, `box.pr`, `box.resume`, `box.revise`, `box.steer`, `approval.approve`; `box.spawn` with a template that has secrets or egress |
| Machine only | policy, config, vault, connectors, egress; enrolling or removing devices (including pairing and revoking); `lockdown.off`; raising caps; uninstall; anything about the audit |

**The touch is not built yet.** Passkey support comes with plan 31. Until
then the daemon refuses every action in the touch row with `touch_required`,
even with a proof. The page says "Needs a touch on a paired passkey" and shows
the machine command. The button never shows success. Do these on the machine.
The machine-side box commands arrive with the box manager.

Machine-only actions are not offered in the page at all. A frame that asks for
one is refused.

## The audit

Every change from the page is recorded by the daemon: reorder, stop, pause,
discard, spawn, lockdown on and so on. Each record has the device id and `via: "local"`.
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
