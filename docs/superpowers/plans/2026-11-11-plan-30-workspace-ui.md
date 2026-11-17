# Plan 30: Workspace UI (W3) on the fake box source: overview, review/revise, steer, inbox, spawn: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The localhost Workspace UI that `saiife workspace serve` (plan 29) serves on `http://localhost:47810/`, built and tested entirely against `FakeBoxSource` (plan 28):
- pairing in the browser (the QR/URL fragment, a non-extractable WebCrypto key, the short code);
- the five §9.3 screens: **Overview**, **Review** (diff, tests, Approve / Reject / Revise), **Steer** (message, pause, stop, reorder), **Approve inbox**, **Spawn**;
- every request a signed frame, every refusal shown by its `rule`; Touch-level actions show the action and its short code and stop at "needs a touch" until plan 31 adds WebAuthn.

**Architecture:**
- **No build step, no dependency.** Hand-written ES modules and one CSS file under `crates/link/assets/`, embedded with `include_bytes!` (`crates/link/src/assets.rs`), served with the strict CSP of plan 29 Task 7. No bundler, npm, CDN, vendored library, inline script, inline style or `eval`.
- **DOM by `textContent` only.** One helper (`js/dom.js` `h()`) builds every element; no module may use `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write` (a Rust test scans the assets). All box data, diff text, paths and labels are hostile by default (plan 28's demo carries such data).
- **Pure logic is separate from views.** `wire.js` (frames, signing), `pairing.js`, `diff.js` (unified-diff parser), `format.js` and `actions.js` touch no DOM and are tested with `node --test` against plan 28's frozen vectors. Views (`views/*.js`) are thin and covered by the Rust static scans plus Rust end-to-end tests that send the same frames the views send (from `actions.js`, the single list of what each button sends).
- The diff is rendered by our own small renderer (§9.4 names diff2html or Monaco; neither is vendored in v3.0, flagged below).

**Tech Stack:** ES2022 modules, WebCrypto (`crypto.subtle`: ECDSA P-256, HMAC-SHA256, SHA-256), IndexedDB (key storage), CSS custom properties. Tests: `node --test` (Node ≥ 20, no packages), Rust integration tests in `crates/link/tests/`. No new Rust crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §9.1, §9.3, §9.4, §9.5, §9.6, §8.3 (short code), §15 (a compromised frontend can mislead; the signature still binds the real action). Contract: `v3-step4-6-contract.md`. Plans 28 and 29 define every Rust name used.

## Contract changes

None. The contract fixes the stack ("vanilla ES modules + CSS in `crates/link/assets/`, `include_bytes!`, strict CSP, no bundler, no CDN, no new deps"); this plan follows it.

Decisions flagged for the owner:
- **No diff2html or Monaco** in v3.0 (§9.4 names them). A 150-line renderer over `textContent` keeps the asset tree free of third-party JS; side-by-side view and syntax colour are later.
- **Polling, not push.** Overview polls `box.overview` every 3 s while the tab is visible; the terminal (plan 31) polls `box.term.read`. Each poll is a signed frame (≈ 1 frame/s at most per tab).
- **The browser key lives in IndexedDB** as a non-extractable `CryptoKey`. Clearing site data unpairs the browser (the device stays listed until `saiife workspace revoke`).

## Facts checked (2026-11-11)

| # | Fact | Source | Result |
|---|---|---|---|
| F1 | `node` v26.8.2 is on the owner's machine; the CI workflow has no node step today. | `node --version`; `grep -n node .github/workflows/ci.yml` (no hit) | Task 1 adds one step `node --test crates/link/assets/tests/`; GitHub's ubuntu runners ship Node 20+. |
| F2 | Node ≥ 20 has `globalThis.crypto.subtle` with ECDSA P-256, HMAC and SHA-256, and `node:test`. | Node docs (webcrypto, test runner) | The signing and pairing code runs unchanged in tests. |
| F3 | `crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"}, false, ["sign"])` gives a non-extractable private key; its public key is extractable (`exportKey("raw")` → 65 bytes). ECDSA `sign` output is P1363 (`r ‖ s`). | W3C WebCrypto | Matches plan 28 F3. |
| F4 | `crates/cli/src/report_html.rs:10-11` holds the colour tokens (`--bg`, `--fg`, `--muted`, `--line`, `--head`, `--bad`, `--warn`) with a `prefers-color-scheme: dark` block. | tree | `app.css` copies them and adds `--ok`, `--accent`. |
| F5 | `history.replaceState` removes the fragment without a navigation; a fragment is never sent to a server. | WHATWG HTML, RFC 3986 §3.5 | `pairing.js` reads the fragment, then removes it at once. |

## Global Constraints

- **Assets:** only these extensions: `.html`, `.css`, `.js`, `.svg`, `.json` (none is fetched from elsewhere). Every file under `crates/link/assets/` (except `assets/tests/`) is in `ASSETS`, and every `ASSETS` entry exists (Task 1 test).
- **Forbidden in any asset** (Rust scan, Task 1): `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `setTimeout("`, `http://` and `https://` (the one exception: `xmlns="http://www.w3.org/2000/svg"` in `.svg` files), `//cdn`, `import(` with a non-literal, `<script>` without `src`, `style=` and `on[a-z]+=` attributes in HTML, `javascript:`. `localStorage` is not used (IndexedDB only, for the key).
- **Copy rules:** short plain sentences; buttons say what they do ("Stop box", "Approve with touch"); refusals show the daemon's `message`, never a stack or a raw JSON dump.
- **Accessibility:** every control is a `<button>` or a labelled input; focus visible; works at 360 px width (phone) and with the keyboard.
- **No network in tests.** `node --test` runs offline on the files; Rust tests use plan 29's in-process stack on `127.0.0.1:0`.
- **Every task** (worktree `.worktrees/p30`, branch `p30-workspace-ui` off `v3-dev` after plan 29 Task 7 merged):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p30-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR"
  export CARGO_INCREMENTAL=0
  node --test crates/link/assets/tests/
  cargo test -p saiife-link -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy -p saiife-link --all-targets -j 4 -- -D warnings
  ```
  Remove `$TMPDIR` at the end. Never commit `.superpowers/`. Trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Hostile box data reaches the page:** the demo's `<img src=x onerror=alert(1)>.md` file name, `../../.ssh/authorized_keys`, an OSC 52 sequence and a U+202E in the task text. Expected: shown as literal text; bidi controls and C0 controls shown as visible escapes (`⟨U+202E⟩`, `⟨ESC⟩`); nothing executes or reorders (Task 1: `assets_never_use_html_sinks`, node `visible escapes bidi and controls`; Task 5: node `diff render keeps hostile text inert`).
2. **The fragment leaks or is reused:** the pairing secret stays in the address bar, the history, a `Referer`, or a second tab pairs with the same fragment. Expected: removed with `replaceState` before any request; `Referrer-Policy: no-referrer`; the second tab gets `pair_expired` (Task 3: node `fragment is cleared before posting`; Rust `second_tab_cannot_reuse_the_offer`).
3. **The daemon restarts or the device is revoked mid-session.** Expected: on `stale_epoch` the UI fetches `/api/hello` once and resends the frame with a new nonce (never the old nonce); on `unknown_device` it shows "This browser is no longer paired" and the pairing screen (Task 2: node `stale epoch refetches hello and re-signs`, `unknown device shows unpaired`).
4. **A Touch action looks like it succeeded.** Expected: `touch_required` shows the action, the box, the short code of the challenge when there is one, and "Needs a touch on a paired passkey" plus the machine command (`saiife box land <id>`); the button never shows a success state (Task 2: node `actions maps touch_required to needs_touch`; Task 4: Rust `steer_is_refused_touch_required`; Task 5: Rust `land_is_refused_touch_required`).
5. **A 2 MB diff or 200 boxes on a phone.** Expected: the diff renders the first 2 000 lines, says how many more and that the daemon truncated it (`truncated`), and stays responsive; the overview lists 200 boxes without layout breakage (Task 5: node `diff render caps lines`; Task 4: Rust `overview_with_200_boxes`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (asset table, shell, CSS, scans, CI step).
- **Wave 2:** Task 2 (wire.js) and Task 3 (pairing) in parallel (both only add files; Task 3 imports `wire.js` names fixed below).
- **Wave 3 (parallel):** Task 4 (overview + steer), Task 5 (review + diff), Task 6 (inbox + spawn). Each adds its own `views/*.js` and its `ASSETS` lines (append at the end of the table; adjacent-line merges only).
- **Last:** Task 7 (docs + end-to-end), gates, whole-branch review, PR.

**Shared files:** `crates/link/src/assets.rs` (`ASSETS` table: one line per file, sorted within each task's block), `js/actions.js` (Task 2 creates it with every action; later tasks only read it), `js/app.js` (Task 1 creates the router with all routes pointing at placeholder views; Tasks 4-6 replace one import line each).

---

### Task 1: the asset table, the shell and the safety scans (size M)

**Files:**
- Create: `crates/link/assets/index.html`, `crates/link/assets/app.css`, `crates/link/assets/js/app.js`, `crates/link/assets/js/dom.js`, `crates/link/assets/js/format.js`, `crates/link/assets/js/views/placeholder.js`, `crates/link/assets/tests/dom.test.mjs`, `crates/link/assets/tests/format.test.mjs`, `crates/link/tests/assets.rs`.
- Modify: `crates/link/src/assets.rs` (replace plan 29's placeholder table), `.github/workflows/ci.yml` (linux test job: a step `node --version && node --test crates/link/assets/tests/`).

**Interfaces (Produces):**
- `index.html`: `<!doctype html>`, `lang="en"`, `<meta name="viewport" content="width=device-width, initial-scale=1">`, `<link rel="stylesheet" href="/app.css">`, `<script type="module" src="/js/app.js">`, a `<header>` with the nav (Overview, Inbox, Spawn), `<main id="view">`, a `<div id="toast" role="status" aria-live="polite">`. No other markup.
- `dom.js`: `export function h(tag, attrs = {}, ...children)` — `children` strings become text nodes; `attrs` allows only `class`, `id`, `type`, `name`, `value`, `placeholder`, `for`, `role`, `aria-*`, `data-*`, `disabled`, `rows`, `maxlength`, `href` (only `#/…`), and `on: {click: fn, …}` for listeners (no attribute handlers); anything else throws. `export function clear(el)`, `export function mount(view)`.
- `format.js`: `export function visible(s)` (C0 and DEL as `⟨ESC⟩`/`⟨U+0007⟩`, bidi controls U+202A–U+202E, U+2066–U+2069, U+200E/F as `⟨U+202E⟩`), `export function ago(seconds)` ("3 min", "2 h"), `export function runtime(started, now)`, `export function short(hex, n = 8)`, `export function bytes(n)`.
- `app.js`: hash router: `#/overview` (default), `#/box/<id>` (review), `#/box/<id>/steer`, `#/inbox`, `#/spawn`, `#/pair`; an unpaired browser (no key in IndexedDB) always goes to `#/pair`. Box ids from the hash are checked against `^[a-z0-9][a-z0-9-]{0,39}$` before use.
- `app.css`: tokens from `report_html.rs:10-11` plus `--ok:#1a7f37` / dark `#7ee2a8` and `--accent:#3b5bdb` / dark `#91a7ff`; a mobile-first one-column layout, cards for boxes, a sticky action bar on Review, `.state-<name>` colours for the seven §7.7 states, monospaced diff with `white-space: pre`, overflow scroll per hunk.
- `assets.rs`: `ASSETS` as plan 29 Task 7 typed it; `mime` from the extension (`text/html; charset=utf-8`, `text/css; charset=utf-8`, `text/javascript; charset=utf-8`, `image/svg+xml`, `application/json`). `GET /` serves `index.html`.

- [ ] **Step 1: Write the failing tests.** Rust `crates/link/tests/assets.rs`: `every_asset_file_is_served` (walk `CARGO_MANIFEST_DIR/assets`, skip `tests/`; each path is in `ASSETS` and vice versa), `assets_never_use_html_sinks` (the Global Constraints list, per file, naming file and line on failure), `index_has_no_inline_script_or_style`, `served_bytes_equal_files` (GET each through plan 29's server, compare to the file). Node `dom.test.mjs` (a 30-line fake `document` in the test file): `h makes text nodes from strings`, `h refuses onclick attribute`, `h refuses javascript href`. Node `format.test.mjs`: `visible escapes bidi and controls`, `ago and runtime`.
- [ ] **Step 2: Run** both → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): Workspace UI shell, asset table and safety scans`.

---

### Task 2: `wire.js`: hello, signed frames, refusals (size M)

**Files:** Create `crates/link/assets/js/wire.js`, `crates/link/assets/js/keystore.js`, `crates/link/assets/js/actions.js`, `crates/link/assets/tests/wire.test.mjs`, `crates/link/assets/tests/actions.test.mjs`; modify `assets.rs`.

**Interfaces (Produces):**
```js
// keystore.js — IndexedDB "saiife-workspace", store "keys", one record "device"
export async function loadDevice();            // -> {key: CryptoKey (private), publicRaw: Uint8Array(65), deviceId, machineId} | null
export async function saveDevice(rec);
export async function forgetDevice();
export function memoryStore();                 // same API, for node tests
// wire.js
export const SIG_DOMAIN = "saiife-wire-v1\n";
export const TTL_SECS = 120;                   // under plan 28's MAX_TTL_SECS (300)
export function b64u(bytes); export function unb64u(s);
export async function deviceIdOf(publicRaw);   // "d-" + 16 hex of SHA-256
export function newNonce();                    // 16 random bytes, b64u
export function buildBody({machineId, epoch, deviceId, action, args, now}); // JSON.stringify of the plan 28 Frame, fields in plan 28's order
export async function sign(key, body);         // b64u(P1363 sig over SIG_DOMAIN ‖ utf8(body))
export class Client {
  constructor({fetch, store, now});            // injected for tests
  async hello();                               // GET /api/hello, cached
  async send(action, args = {}, opts = {});    // opts.touch: a plan 28 TouchProof (plan 31); -> {ok:true, result} | {ok:false, rule, message}
}
// actions.js — the one list of what each button sends; views import it
export const ACTIONS = { overview: "box.overview", diff: "box.diff", stop: "box.stop", pause: "box.pause", discard: "box.discard", reorder: "box.reorder", steer: "box.steer", revise: "box.revise", land: "box.land", resume: "box.resume", inbox: "box.inbox", templates: "box.templates", spawn: "box.spawn", whoami: "workspace.whoami", lockdownOn: "lockdown.on" };
export function outcome(answer);               // -> "done" | "needs_touch" | "unpaired" | "pending" | "retry" | "refused"
```
- `Client.send`: builds a fresh body per attempt; on `rule: "stale_epoch"` it drops the cached hello, fetches it once and resends with a **new** nonce; on any other refusal it returns it. A daemon 503 is `{ok:false, rule:"unreachable", message:"The saiife daemon is not reachable"}`.
- `outcome`: `touch_required` → `needs_touch`; `unknown_device` → `unpaired`; `device_pending` → `pending`; `busy`/`unreachable` → `retry`; otherwise `refused`.

- [ ] **Step 1: Write the failing node tests:** `frozen frame vector verifies` (read `../../../wire/tests/vectors/frame-v1.json` with `node:fs`; `crypto.subtle.verify` with the raw public key over `SIG_DOMAIN + body` is true, the `bad_sig` false), `sign then verify`, `body has plan 28 fields only` (keys equal `["v","machine_id","epoch","device_id","action","args","nonce","issued_at","expires_at"]`, `expires_at - issued_at === 120`), `device id matches vector`, `stale epoch refetches hello and re-signs` (fake fetch: first answer `stale_epoch`, then ok; two different nonces were sent, hello fetched twice), `unknown device shows unpaired`, `actions maps touch_required to needs_touch`, `every action name is in the Rust table` (parse `crates/wire/src/level.rs` text for the `REMOTE` names; each `ACTIONS` value is there).
- [ ] **Step 2: Write the failing Rust test** `crates/link/tests/js_interop.rs::node_signed_frame_verifies_in_rust`: if `node` is not found on `PATH` (checked with `std::process::Command::new("node").arg("--version")`), print `skipped: no node` and return; else run `node crates/link/assets/tests/sign-once.mjs` (a 20-line script that generates a key, prints `{public_raw, body, sig}` as JSON) and verify it with `saiife_wire::sig::verify_p256`. This pins the JS → Rust direction; the vector pins Rust → JS.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(link): wire.js: signed frames from the browser, refusals by rule`.

---

### Task 3: pairing in the browser (size M)

**Files:** Create `crates/link/assets/js/pairing.js`, `crates/link/assets/js/views/pair.js`, `crates/link/assets/tests/pairing.test.mjs`; modify `assets.rs`, `js/app.js` (the `#/pair` import). **Test (Rust):** `crates/link/tests/ui_flows.rs` (new; plan 29's in-process stack with `FakeBoxSource::demo`).

**Interfaces (Produces):**
```js
// pairing.js (no DOM)
export function parseFragment(hash);           // "#pair=<b64u>" -> {pairId, secret: Uint8Array(32), machineId, machinePub: Uint8Array(65)} | null
export async function proof(secret, pairId, devicePub);   // HMAC-SHA256(secret, "saiife-pair-v1\n" ‖ pairId ‖ devicePub)
export async function shortCode(machinePub, devicePub, secret);   // "NNN NNN", as plan 28
export async function pair({hash, location, history, fetch, store, label}); // -> {deviceId, shortCode} | {error}
```
- Order inside `pair`: parse → `history.replaceState(null, "", location.pathname)` (the fragment is gone before anything else) → check `machineId` equals `/api/hello`'s → generate the non-extractable key → compute proof and code → POST `/api/pair` → compare the daemon's `short_code` with ours (differ: show "Codes differ: do not confirm on the machine" and forget the key) → save the device → show the code big, with "Check that your machine shows the same code, then confirm there" → poll `workspace.whoami` every 2 s; `pending` keeps waiting, `done` goes to `#/overview`.
- The view's label input defaults to the browser's `navigator.platform`-free text "Browser on this machine"; 1–40 chars (plan 28's rule).

- [ ] **Step 1: Write the failing node tests:** `frozen pair vector` (`pair-v1.json`: proof and short code equal), `parseFragment rejects junk` (missing `pair=`, bad b64u, wrong lengths), `fragment is cleared before posting` (fake `history` records the call before the fake `fetch` sees any request), `machine id mismatch stops`, `codes that differ forget the key`.
- [ ] **Step 2: Write the failing Rust tests** (`ui_flows.rs`, driving the server with the bodies `pairing.js` sends, built in Rust from plan 28's `TestDevice`): `pair_then_overview` (pair.begin through the control socket, POST `/api/pair`, confirm, then `box.overview` ok), `second_tab_cannot_reuse_the_offer`, `pending_device_is_device_pending`.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(link): pair a browser: fragment, WebCrypto key, short code`.

---

### Task 4: Overview and Steer (size M)

**Files:** Create `crates/link/assets/js/views/overview.js`, `crates/link/assets/js/views/steer.js`, `crates/link/assets/js/touchprompt.js`; modify `assets.rs`, `js/app.js`, `crates/link/tests/ui_flows.rs`.

**Interfaces (Produces):**
- `overview.js` `export function view(client)`: polls `ACTIONS.overview` every 3 s while `document.visibilityState === "visible"`; header line "N running · M queued · K free slots · CPU x% · RAM a/b GB" (`load` may be `null`: omit that part); one card per box in the DTO order: state badge, `visible(task)` (first 140 chars, full text on tap), `template`, `repo`, run time; Done boxes link to `#/box/<id>`; Running/Paused link to `#/box/<id>/steer`. A queued box has ↑/↓ buttons that send `ACTIONS.reorder` with the full new order. A "Lockdown on" button in the header sends `ACTIONS.lockdownOn` after a confirm ("Stop every agent on this machine?").
- `steer.js` `export function view(client, id)`: textarea (max 4096 bytes, counter) → `ACTIONS.steer {id, msg}`; buttons Pause (`ACTIONS.pause`), Resume (`ACTIONS.resume`), Stop (`ACTIONS.stop`, with confirm). Plan 31 adds the terminal pane above.
- `touchprompt.js` `export function show(refusal, {action, id, summary})`: the panel for `needs_touch`: what was asked, the box id, the short code when the answer has `short_code`, "Needs a touch on a paired passkey", and the machine command (`saiife box land <id>`, `saiife box say <id> "…"` per action). Plan 31 adds the "Touch now" button here.

- [ ] **Step 1: Write the failing Rust tests** (`ui_flows.rs`): `overview_lists_demo_boxes` (4 boxes, order running, done, queued×2), `overview_with_200_boxes` (a `FakeBoxSource` with 200 boxes; one frame < 1 s and < 1 MB), `stop_and_pause_run` (`FakeCall::Stop`, `FakeCall::Pause` recorded with the device in the audit record), `reorder_sends_full_order`, `steer_is_refused_touch_required`, `lockdown_on_from_ui`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `node --test` still passes.
- [ ] **Step 5: Commit** `feat(link): Overview and Steer screens`.

---

### Task 5: Review: the diff, tests, Approve / Reject / Revise (size M)

**Files:** Create `crates/link/assets/js/diff.js`, `crates/link/assets/js/views/review.js`, `crates/link/assets/tests/diff.test.mjs`; modify `assets.rs`, `js/app.js`, `crates/link/tests/ui_flows.rs`.

**Interfaces (Produces):**
```js
// diff.js (no DOM in parse)
export function parse(unified);   // -> [{oldPath, newPath, binary, hunks: [{header, lines: [{kind: "+"|"-"|" "|"\\", text, oldNo, newNo}]}]}]
export function render(files, h, {maxLines = 2000});   // -> DOM nodes via h(); returns {nodes, shownLines, hiddenLines}
```
- `review.js` `export function view(client, id)`: `ACTIONS.diff {id}` → header: box id, base commit (`short`), `diff_sha256` (`short`, full on tap), files changed with `+a −r` per file (`binary` shown as "binary"); a tests line (`passed/failed/skipped` and `visible(summary)`), red when `failed > 0`; a banner when `truncated` ("The diff is larger than 2 MB; review the rest on the machine: `saiife box diff <id>`"). Sticky bar: **Approve with touch** (`ACTIONS.land {id, diff_sha256}` → `needs_touch` → `touchprompt.show`), **Reject** (`ACTIONS.discard {id}` after confirm "Discard this box's work?"), **Revise** (textarea → `ACTIONS.revise {id, comment}` → `needs_touch` until plan 31).
- Paths are shown with `visible()`, never resolved or turned into links; `../` stays literal.

- [ ] **Step 1: Write the failing node tests:** `parse counts lines` (a two-file diff: `+3 −1`, line numbers), `parse no newline marker`, `parse rename and binary`, `parse crlf keeps cr visible`, `diff render keeps hostile text inert` (the demo's hostile file name and the OSC 52 line become text nodes containing `⟨ESC⟩`), `diff render caps lines` (5 000 lines → `shownLines 2000`, `hiddenLines 3000`).
- [ ] **Step 2: Write the failing Rust tests:** `diff_of_done_box` (the demo `b-done`: `truncated: true`, the hostile path byte for byte), `land_is_refused_touch_required`, `reject_discards` (`FakeCall::Discard`), `revise_is_refused_touch_required`.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement.** **Step 5: Run** → PASS.
- [ ] **Step 6: Commit** `feat(link): Review screen with an inert diff renderer`.

---

### Task 6: Approve inbox and Spawn (size M)

**Files:** Create `crates/link/assets/js/views/inbox.js`, `crates/link/assets/js/views/spawn.js`; modify `assets.rs`, `js/app.js`, `crates/link/tests/ui_flows.rs`.

**Interfaces (Produces):**
- `inbox.js` `export function view(client)`: `ACTIONS.inbox` → one row per `PendingView`: class (`land`, `push_protected`, …, as words: "Land into repo", "Push to protected branch"), `visible(summary)`, the box link, the short code (6 digits, plan 26), time left until `expires_at` (expired rows greyed, no button). Tapping a row opens `touchprompt.show` for it. **No row is a link that approves** (§9.6): there is no URL that approves anything, and plan 31's touch is the only way.
- `spawn.js` `export function view(client)`: `ACTIONS.templates` → template picker (each with `visible(description)` and a "needs a touch" badge when `has_secrets || has_egress`); fields repo (1–200 chars, the display name the box manager knows), task (≤ 8192 bytes, counter), Start now / Queue → `ACTIONS.spawn {template, repo, task, start: "now"|"queue"}` → `done` goes to `#/overview`; `needs_touch` → `touchprompt.show`.

- [ ] **Step 1: Write the failing Rust tests:** `inbox_lists_demo_land` (one `land` item whose `short_code` equals `saiife_touch::short_code` of its challenge), `spawn_plain_template_queues` (`FakeCall::Spawn` with `start: Queue`), `spawn_secret_template_needs_touch`, `spawn_task_with_escape_is_refused` (`\x1b` in task → `invalid`), and a static test `inbox_has_no_approve_url` (the `inbox.js` text contains no `href` built from a request id and no `land` call outside `touchprompt`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(link): Approve inbox and Spawn screens`.

---

### Task 7: docs and the end-to-end pass (size S)

**Files:** Create `docs/workspace.md`; modify `crates/link/tests/ui_flows.rs`.

- `docs/workspace.md`: what the Workspace is (localhost now; app.saiife.com when the hub ships), `saiife workspace pair --local`, `saiife workspace serve`, what needs a touch and why (the §9.5 table as plan 28 fixed it), what is machine-only, revoking a browser, the honest limits from §15 (a compromised frontend can mislead what you see; the touch still binds the real action; synced passkeys), and that the debug-only `fake-boxes` feature exists for trying the UI before boxes ship (never in a release).
- [ ] **Step 1: Write the failing test** `whole_flow_on_fake` (`ui_flows.rs`): pair → overview → reorder → stop → diff of `b-done` → reject → spawn plain → inbox; audit records exist for reorder, stop, discard, spawn (each with `via: "local"` and the device id); none for overview, diff or inbox reads.
- [ ] **Step 2: Run** → it may already pass, since Tasks 3–6 built every piece; if it fails, the failure names the missing piece: fix it in the owning file. **Step 3: Write** `docs/workspace.md`. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `docs(workspace): the localhost Workspace; end-to-end test on the fake`.

---

## Gates (after Task 7)

- [ ] `node --test crates/link/assets/tests/` and `cargo test -p saiife-link -j 4 -- --test-threads=4`.
- [ ] `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `bash scripts/check-windows.sh -p saiife-link`.
- [ ] `git diff v3-dev -- Cargo.lock` is empty.
- [ ] Owner handwork (not agents): `cargo run -p saiife-daemon --features fake-boxes` in a personal test setup, `saiife workspace pair --local`, `saiife workspace serve`, then click through the five screens in Firefox and Chrome, at phone width. Report anything that looks wrong to the coordinator.
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Out of scope

- The Workspace mode of app.saiife.com (`../saiife.com`, Next.js) and the hub relay (`../saiife-hub`): other repos. They can reuse `wire.js` and `pairing.js` as reference and must pass plan 28's vectors.
- WebAuthn, the "Touch now" button, terminal pane, `approval.*` items in the inbox: plan 31.
