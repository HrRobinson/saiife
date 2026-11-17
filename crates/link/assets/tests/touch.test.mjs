import test from "node:test";
import assert from "node:assert/strict";
import { touch, proofOf, getOptions, PROMPT_TIMEOUT_MS, NOT_APPROVED } from "../js/touch.js";
import { Client, b64u, unb64u, deviceIdOf } from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";
import { outcome } from "../js/actions.js";

// A tiny fake document (as dom.test.mjs).
class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...kids) { this.children.push(...kids); }
  replaceChildren(...kids) { this.children = kids; }
}
globalThis.document = {
  createElement: (t) => new Node_(t),
  createTextNode: (s) => ({ text: s }),
};
function text(n) {
  if (n instanceof Node_) return n.children.map(text).join("");
  return n && typeof n.text === "string" ? n.text : "";
}

const P256 = { name: "ECDSA", namedCurve: "P-256" };
const CHALLENGE = "ab".repeat(32);
const CRED_ID = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const OTHER_ID = new Uint8Array([9, 9, 9, 9]);

const BEGIN = {
  rp_id: "localhost",
  challenge: CHALLENGE,
  allow: [b64u(CRED_ID)],
  uv: true,
  summary: "box.steer box b-run",
  short_code: "042917",
  request_id: "7",
  expires_at: 1700000300,
  class: "steer",
};

const HELLO = (epoch) => ({
  ok: true,
  result: { machine_id: "0123456789abcdef0123456789abcdef", machine_pub: "AA", epoch, frame_version: 1 },
});

function fakeFetch(script) {
  const calls = [];
  const f = async (url, init = {}) => {
    calls.push({ url, init });
    const [status, payload] = script.shift();
    const body = typeof payload === "string" ? payload : JSON.stringify(payload);
    return new Response(body, { status, headers: { "content-type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

async function client(script) {
  const store = memoryStore();
  const pair = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  await store.saveDevice({ key: pair.privateKey, publicRaw, deviceId: await deviceIdOf(publicRaw), machineId: "m" });
  const fetch = fakeFetch(script);
  return { c: new Client({ fetch, store, now: () => 1700000000 }), fetch };
}

const frames = (fetch) =>
  fetch.calls.filter((x) => x.url === "/api/frame").map((x) => JSON.parse(x.init.body));

const buf = (a) => new Uint8Array(a).buffer;

// A fake PublicKeyCredential for `rawId`.
function credential(rawId = CRED_ID) {
  return {
    type: "public-key",
    id: b64u(rawId),
    rawId: buf(rawId),
    response: {
      authenticatorData: buf([0xaa, 0xbb]),
      clientDataJSON: buf([0x7b, 0x7d]),
      signature: buf([0x30, 0x01]),
    },
  };
}

function fakeCredentials(result, seen = {}) {
  return {
    calls: 0,
    async get(opts) {
      this.calls++;
      seen.opts = opts;
      if (seen.check) seen.check();
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

test("get options are as fixed", async () => {
  const o = getOptions({ challenge: CHALLENGE, allow: [b64u(CRED_ID)] }, "localhost");
  assert.deepEqual(Object.keys(o), ["publicKey"]);
  const p = o.publicKey;
  assert.deepEqual(Object.keys(p).sort(), ["allowCredentials", "challenge", "rpId", "timeout", "userVerification"]);
  assert.deepEqual(Array.from(p.challenge), Array(32).fill(0xab));
  assert.equal(p.rpId, "localhost");
  assert.equal(p.userVerification, "required");
  assert.equal(p.timeout, 120000);
  assert.equal(PROMPT_TIMEOUT_MS, 120000);
  assert.equal(p.allowCredentials.length, 1);
  assert.equal(p.allowCredentials[0].type, "public-key");
  assert.deepEqual(Array.from(p.allowCredentials[0].id), Array.from(CRED_ID));

  // touch() hands the same options to credentials.get.
  const { c } = await client([
    [200, HELLO("e1")],
    [200, { ok: true, result: BEGIN }],
    [200, { ok: true, result: {} }],
  ]);
  const seen = {};
  const a = await touch(c, { action: "box.steer", args: { id: "b-run", msg: "hi" }, credentials: fakeCredentials(credential(), seen), rpId: "localhost" });
  assert.deepEqual(a, { ok: true, result: {} });
  assert.deepEqual(seen.opts, getOptions(BEGIN, "localhost"));
});

test("short code shows before the dialog", async () => {
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, { ok: true, result: BEGIN }],
    [200, { ok: true, result: {} }],
  ]);
  const mounted = [];
  const seen = {};
  seen.check = () => {
    // When the dialog opens, the prompt with the code is on the page.
    seen.atGet = mounted.map(text);
  };
  const a = await touch(c, {
    action: "box.steer",
    args: { id: "b-run", msg: "hi" },
    credentials: fakeCredentials(credential(), seen),
    rpId: "localhost",
    mount: (node) => mounted.push(node),
  });
  assert.equal(a.ok, true);
  assert.equal(seen.atGet.length, 1, "the prompt was mounted before credentials.get");
  const shown = seen.atGet[0];
  assert.ok(shown.includes("042917"), shown);
  assert.ok(shown.includes("Touch now"), shown);
  assert.ok(shown.includes("box.steer box b-run"), shown);
  assert.ok(shown.includes("b-run"), shown);
  assert.ok(shown.includes("Face ID, fingerprint or PIN"), shown);
  // begin first, then the touched frame with the proof.
  const [b, f] = frames(fetch);
  assert.equal(JSON.parse(b.body).action, "workspace.touch.begin");
  assert.deepEqual(JSON.parse(b.body).args, { action: "box.steer", args: { id: "b-run", msg: "hi" } });
  assert.equal(b.touch, undefined);
  assert.equal(JSON.parse(f.body).action, "box.steer");
  assert.deepEqual(f.touch, proofOf("7", credential()));
});

test("cancel is not approved", async () => {
  for (const result of [
    Object.assign(new Error("cancelled"), { name: "NotAllowedError" }),
    Object.assign(new Error("timeout"), { name: "AbortError" }),
    null,
    credential(OTHER_ID), // a passkey the daemon did not allow
    { type: "public-key", rawId: buf(CRED_ID), response: {} }, // no assertion
  ]) {
    const { c, fetch } = await client([
      [200, HELLO("e1")],
      [200, { ok: true, result: BEGIN }],
    ]);
    const mounted = [];
    const a = await touch(c, { action: "box.steer", args: { id: "b-run", msg: "hi" }, credentials: fakeCredentials(result), rpId: "localhost", mount: (n) => mounted.push(n) });
    assert.equal(a.ok, false);
    assert.equal(a.error, "not_approved");
    assert.equal(a.message, NOT_APPROVED);
    assert.equal(outcome(a), "refused");
    // Only the begin frame went out.
    assert.equal(frames(fetch).length, 1);
    assert.ok(text(mounted.at(-1)).includes("Not approved"));
  }
  // No WebAuthn at all: not approved, nothing sent after begin.
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, { ok: true, result: BEGIN }],
  ]);
  const a = await touch(c, { action: "box.steer", args: { id: "b-run" }, credentials: undefined, rpId: "localhost" });
  assert.equal(a.error, "not_approved");
  assert.equal(frames(fetch).length, 1);
});

test("a refused begin is returned as is; a bad begin answer sends nothing", async () => {
  const no = { ok: false, error: "unavailable", rule: "touch_unavailable", message: "this browser has no passkey" };
  let { c, fetch } = await client([[200, HELLO("e1")], [200, no]]);
  const creds = fakeCredentials(credential());
  let a = await touch(c, { action: "box.steer", args: { id: "b-run" }, credentials: creds, rpId: "localhost" });
  assert.equal(a.rule, "touch_unavailable");
  assert.equal(creds.calls, 0);
  for (const bad of [
    { ...BEGIN, short_code: "12345" },
    { ...BEGIN, challenge: "zz" },
    { ...BEGIN, allow: [] },
    { ...BEGIN, allow: ["+/="] },
    { ...BEGIN, request_id: "x" },
  ]) {
    ({ c, fetch } = await client([[200, HELLO("e1")], [200, { ok: true, result: bad }]]));
    a = await touch(c, { action: "box.steer", args: { id: "b-run" }, credentials: creds, rpId: "localhost" });
    assert.equal(a.ok, false);
    assert.equal(a.error, "bad_answer");
    assert.equal(frames(fetch).length, 1);
  }
  assert.equal(creds.calls, 0);
});

test("a given request skips begin", async () => {
  const { c, fetch } = await client([[200, HELLO("e1")], [200, { ok: true, result: {} }]]);
  const a = await touch(c, {
    action: "box.land",
    args: { id: "b-done", diff_sha256: "cd".repeat(32) },
    requestId: "42",
    request: { challenge: CHALLENGE, allow: [b64u(CRED_ID)], short_code: "123456", summary: "land b-done" },
    credentials: fakeCredentials(credential()),
    rpId: "localhost",
  });
  assert.equal(a.ok, true);
  const [f] = frames(fetch);
  assert.equal(JSON.parse(f.body).action, "box.land");
  assert.equal(f.touch.request_id, "42");
});

test("stale epoch resends the same proof once", async () => {
  const stale = { ok: false, error: "stale_epoch", rule: "stale_epoch", message: "Stale epoch" };
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, { ok: true, result: BEGIN }],
    [200, stale],
    [200, HELLO("e2")],
    [200, { ok: true, result: { done: 1 } }],
  ]);
  const creds = fakeCredentials(credential());
  const a = await touch(c, { action: "box.steer", args: { id: "b-run", msg: "hi" }, credentials: creds, rpId: "localhost" });
  assert.deepEqual(a, { ok: true, result: { done: 1 } });
  assert.equal(creds.calls, 1, "one touch only");
  const [, one, two] = frames(fetch);
  assert.deepEqual(one.touch, two.touch);
  assert.notEqual(JSON.parse(one.body).nonce, JSON.parse(two.body).nonce);
  assert.equal(JSON.parse(two.body).epoch, "e2");
});

test("proofOf is b64u of the assertion", () => {
  const p = proofOf("7", credential());
  assert.deepEqual(p, {
    request_id: "7",
    credential_id: b64u(CRED_ID),
    authenticator_data: b64u(new Uint8Array([0xaa, 0xbb])),
    client_data_json: b64u(new Uint8Array([0x7b, 0x7d])),
    signature: b64u(new Uint8Array([0x30, 0x01])),
  });
  for (const k of Object.keys(p)) assert.doesNotThrow(() => k === "request_id" || unb64u(p[k]));
});

// readAnswer, through Client.send (it is not exported).
const TR = { rp_id: "localhost", challenge: CHALLENGE, allow: [b64u(CRED_ID)], uv: true, summary: "deploy", short_code: "654321" };

test("read answer keeps short code and touch", async () => {
  const { c } = await client([
    [200, HELLO("e1")],
    [200, { ok: false, error: "forbidden", rule: "touch_required", message: "needs a touch", short_code: "123456", touch: TR }],
  ]);
  const a = await c.send("approval.approve", { id: 3 });
  assert.deepEqual(a, { ok: false, error: "forbidden", rule: "touch_required", message: "needs a touch", short_code: "123456", touch: TR });
  assert.equal(outcome(a), "needs_touch");
});

test("read answer drops other fields", async () => {
  const base = { ok: false, error: "forbidden", rule: "touch_required", message: "m" };
  const want = { ok: false, error: "forbidden", rule: "touch_required", message: "m" };
  for (const extra of [
    { result: { x: 1 }, link: "https://evil.test/approve", html: "<b>" },
    { short_code: "12345" },
    { short_code: "1234567" },
    { short_code: "12345a" },
    { short_code: "１２３４５６" },
    { short_code: 123456 },
    { touch: { ...TR, approve_url: "https://evil.test" } },
    { touch: { rp_id: "localhost" } },
    { touch: [TR] },
    { touch: "x" },
    { touch: { ...TR, allow: "AQID" } },
    { touch: { ...TR, uv: "yes" } },
  ]) {
    const { c } = await client([[200, HELLO("e1")], [200, { ...base, ...extra }]]);
    assert.deepEqual(await c.send("box.land", { id: "b" }), want, JSON.stringify(extra));
  }
  // An ok answer keeps its result whole and nothing else.
  const { c } = await client([[200, HELLO("e1")], [200, { ok: true, result: { a: [1] }, short_code: "123456" }]]);
  assert.deepEqual(await c.send("box.overview"), { ok: true, result: { a: [1] } });
});

test("pending land comes from the inbox and whoami", async () => {
  const item = (id, box, created) => ({ request_id: id, class: "land", box_id: box, summary: `land ${box}`, challenge_hex: CHALLENGE, short_code: "111222", created_at: created, expires_at: 9 });
  const scripted = (answers) => ({ sent: [], async send(a) { this.sent.push(a); return answers.shift(); } });
  const { pendingLand } = await import("../js/touch.js");
  let c = scripted([
    { ok: true, result: { items: [item("1", "b-x", 5), item("2", "b-done", 5), item("3", "b-done", 9), { ...item("4", "b-done", 99), class: "push_protected" }] } },
    { ok: true, result: { device_id: "d", passkeys: [b64u(CRED_ID)] } },
  ]);
  assert.deepEqual(await pendingLand(c, "b-done"), {
    requestId: "3",
    request: { challenge: CHALLENGE, allow: [b64u(CRED_ID)], short_code: "111222", summary: "land b-done" },
  });
  // No pending land, or no passkey the daemon holds: none.
  c = scripted([{ ok: true, result: { items: [item("1", "b-x", 5)] } }]);
  assert.equal(await pendingLand(c, "b-done"), null);
  c = scripted([{ ok: true, result: { items: [item("1", "b-done", 5)] } }, { ok: true, result: { passkeys: [] } }]);
  assert.equal(await pendingLand(c, "b-done"), null);
  c = scripted([{ ok: true, result: { items: [item("1", "b-done", 5)] } }, { ok: true, result: {} }]);
  assert.equal(await pendingLand(c, "b-done"), null);
});
