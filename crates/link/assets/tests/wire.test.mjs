import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  SIG_DOMAIN,
  TTL_SECS,
  b64u,
  unb64u,
  deviceIdOf,
  newNonce,
  buildBody,
  sign,
  Client,
} from "../js/wire.js";
import { memoryStore } from "../js/keystore.js";
import { outcome } from "../js/actions.js";

const vector = JSON.parse(
  readFileSync(new URL("../../../wire/tests/vectors/frame-v1.json", import.meta.url), "utf8"),
);
const enc = new TextEncoder();
const P256 = { name: "ECDSA", namedCurve: "P-256" };
const VERIFY = { name: "ECDSA", hash: "SHA-256" };

function signed(body) {
  const b = enc.encode(body);
  const m = new Uint8Array(SIG_DOMAIN.length + b.length);
  m.set(enc.encode(SIG_DOMAIN), 0);
  m.set(b, SIG_DOMAIN.length);
  return m;
}

async function verifyRaw(publicRaw, body, sigB64u) {
  const pub = await crypto.subtle.importKey("raw", publicRaw, P256, false, ["verify"]);
  return crypto.subtle.verify(VERIFY, pub, unb64u(sigB64u), signed(body));
}

async function newDevice() {
  const pair = await crypto.subtle.generateKey(P256, false, ["sign", "verify"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    key: pair.privateKey,
    publicRaw,
    deviceId: await deviceIdOf(publicRaw),
    machineId: "0123456789abcdef0123456789abcdef",
  };
}

const HELLO = (epoch) => ({
  ok: true,
  result: {
    machine_id: "0123456789abcdef0123456789abcdef",
    machine_pub: "AA",
    epoch,
    frame_version: 1,
  },
});

// A fake fetch: answers in order from `script` (status, json or raw text),
// records every call.
function fakeFetch(script) {
  const calls = [];
  const f = async (url, init = {}) => {
    calls.push({ url, init });
    const next = script.shift();
    if (next instanceof Error) throw next;
    const [status, payload] = next;
    const text = typeof payload === "string" ? payload : JSON.stringify(payload);
    return new Response(text, { status, headers: { "content-type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

async function client(script, device) {
  const store = memoryStore();
  if (device !== null) await store.saveDevice(device ?? (await newDevice()));
  const fetch = fakeFetch(script);
  return { c: new Client({ fetch, store, now: () => 1700000000 }), fetch, store };
}

const frames = (fetch) =>
  fetch.calls.filter((x) => x.url === "/api/frame").map((x) => JSON.parse(x.init.body));

test("frozen frame vector verifies", async () => {
  const pub = unb64u(vector.public_raw_b64u);
  assert.equal(pub.length, 65);
  assert.equal(await verifyRaw(pub, vector.body, vector.sig_b64u), true);
  assert.equal(await verifyRaw(pub, vector.body, vector.bad_sig_b64u), false);
});

test("device id matches vector", async () => {
  assert.equal(await deviceIdOf(unb64u(vector.public_raw_b64u)), vector.device_id);
});

test("b64u is url-safe without padding and strict", () => {
  assert.equal(b64u(new Uint8Array([0xfb, 0xff])), "-_8");
  assert.deepEqual(unb64u("-_8"), new Uint8Array([0xfb, 0xff]));
  assert.throws(() => unb64u("AA=="));
  assert.throws(() => unb64u("+/8"));
  assert.throws(() => unb64u("A"));
  const n = newNonce();
  assert.equal(unb64u(n).length, 16);
  assert.notEqual(n, newNonce());
});

test("sign then verify", async () => {
  const d = await newDevice();
  const body = buildBody({
    machineId: d.machineId,
    epoch: "e",
    deviceId: d.deviceId,
    action: "box.list",
    args: {},
    now: 1700000000,
  });
  const sig = await sign(d.key, body);
  assert.equal(unb64u(sig).length, 64);
  assert.equal(await verifyRaw(d.publicRaw, body, sig), true);
  assert.equal(await verifyRaw(d.publicRaw, body + " ", sig), false);
});

test("body has plan 28 fields only", () => {
  const body = buildBody({
    machineId: "m",
    epoch: "e",
    deviceId: "d-0011223344556677",
    action: "box.stop",
    args: { id: "b1" },
    now: 1700000000,
  });
  const f = JSON.parse(body);
  assert.deepEqual(Object.keys(f), [
    "v",
    "machine_id",
    "epoch",
    "device_id",
    "action",
    "args",
    "nonce",
    "issued_at",
    "expires_at",
  ]);
  assert.equal(f.v, 1);
  assert.equal(f.issued_at, 1700000000);
  assert.equal(f.expires_at - f.issued_at, 120);
  assert.equal(TTL_SECS, 120);
  assert.deepEqual(f.args, { id: "b1" });
  assert.equal(unb64u(f.nonce).length, 16);
  assert.throws(() => buildBody({ machineId: "m", epoch: "e", deviceId: "d", action: "x", args: [], now: 1 }));
});

test("send posts only body and sig with a JSON content type", async () => {
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, { ok: true, result: { boxes: [] } }],
  ]);
  const a = await c.send("box.overview");
  assert.deepEqual(a, { ok: true, result: { boxes: [] } });
  const post = fetch.calls[1];
  assert.equal(post.url, "/api/frame");
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers["Content-Type"], "application/json");
  const sent = JSON.parse(post.init.body);
  assert.deepEqual(Object.keys(sent), ["body", "sig"]);
  const f = JSON.parse(sent.body);
  assert.equal(f.epoch, "e1");
  assert.equal(f.machine_id, "0123456789abcdef0123456789abcdef");
  assert.equal(f.action, "box.overview");
  // The hello is cached: a second send does not fetch it again.
  await c.send("box.overview").catch(() => {});
  assert.equal(fetch.calls.filter((x) => x.url === "/api/hello").length, 1);
});

test("send passes a touch proof through", async () => {
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, { ok: false, error: "touch_required", rule: "touch_required", message: "Needs a touch" }],
  ]);
  const touch = {
    request_id: "r",
    credential_id: "c",
    authenticator_data: "a",
    client_data_json: "j",
    signature: "s",
  };
  const a = await c.send("box.land", { id: "b1" }, { touch });
  assert.equal(outcome(a), "needs_touch");
  assert.deepEqual(frames(fetch)[0].touch, touch);
});

test("stale epoch refetches hello and re-signs", async () => {
  const stale = { ok: false, error: "stale_epoch", rule: "stale_epoch", message: "Stale epoch" };
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, stale],
    [200, HELLO("e2")],
    [200, { ok: true, result: 1 }],
  ]);
  const a = await c.send("box.stop", { id: "b1" });
  assert.deepEqual(a, { ok: true, result: 1 });
  assert.equal(fetch.calls.filter((x) => x.url === "/api/hello").length, 2);
  const [one, two] = frames(fetch).map((x) => JSON.parse(x.body));
  assert.notEqual(one.nonce, two.nonce);
  assert.equal(one.epoch, "e1");
  assert.equal(two.epoch, "e2");
  assert.notEqual(frames(fetch)[0].sig, frames(fetch)[1].sig);
});

test("stale epoch is retried once only", async () => {
  const stale = { ok: false, error: "stale_epoch", rule: "stale_epoch", message: "Stale epoch" };
  const { c, fetch } = await client([
    [200, HELLO("e1")],
    [200, stale],
    [200, HELLO("e2")],
    [200, stale],
  ]);
  const a = await c.send("box.stop", { id: "b1" });
  assert.equal(a.rule, "stale_epoch");
  assert.equal(outcome(a), "refused");
  assert.equal(frames(fetch).length, 2);
});

test("unknown device shows unpaired", async () => {
  const { c } = await client([
    [200, HELLO("e1")],
    [200, { ok: false, error: "unknown_device", rule: "unknown_device", message: "Unknown device" }],
  ]);
  const a = await c.send("box.overview");
  assert.equal(a.ok, false);
  assert.equal(a.message, "Unknown device");
  assert.equal(outcome(a), "unpaired");
  // No device in the store at all is unpaired too, and sends nothing.
  const none = await client([], null);
  const b = await none.c.send("box.overview");
  assert.equal(outcome(b), "unpaired");
  assert.equal(none.fetch.calls.length, 0);
});

test("daemon down is retry with a fixed sentence", async () => {
  const { c } = await client([
    [200, HELLO("e1")],
    [503, { ok: false, error: "unreachable", rule: null, message: "connect: os error 2 at /run/x" }],
  ]);
  const a = await c.send("box.overview");
  assert.deepEqual(a, {
    ok: false,
    error: "unreachable",
    rule: null,
    message: "The saiife daemon is not reachable",
  });
  assert.equal(outcome(a), "retry");
});

test("link errors and junk never surface raw text", async () => {
  for (const [status, payload] of [
    [403, { ok: false, error: "bad_origin" }],
    [500, "<html>stack trace at foo.rs:1</html>"],
    [200, "not json {"],
    [200, { what: 1 }],
  ]) {
    const { c } = await client([[200, HELLO("e1")], [status, payload]]);
    const a = await c.send("box.overview");
    assert.equal(a.ok, false, String(status));
    assert.equal(a.rule, null);
    assert.equal(typeof a.error, "string");
    assert.ok(!a.message.includes("{") && !a.message.includes("<"), a.message);
    assert.ok(!a.message.includes("stack"), a.message);
    assert.equal(outcome(a), "refused");
  }
  const { c } = await client([[200, HELLO("e1")], [403, { ok: false, error: "bad_origin" }]]);
  assert.equal((await c.send("box.overview")).error, "bad_origin");
  const down = await client([new TypeError("Failed to fetch")]);
  const d = await down.c.send("box.overview");
  assert.equal(d.error, "unreachable");
  assert.equal(outcome(d), "retry");
});

test("a failed hello is not cached", async () => {
  const { c, fetch } = await client([
    [503, { ok: false, error: "unreachable", rule: null, message: "x" }],
    [200, HELLO("e1")],
    [200, { ok: true, result: 2 }],
  ]);
  assert.equal(outcome(await c.send("box.overview")), "retry");
  assert.deepEqual(await c.send("box.overview"), { ok: true, result: 2 });
  assert.equal(fetch.calls.filter((x) => x.url === "/api/hello").length, 2);
});

test("an oversized body is refused before sending", async () => {
  const { c, fetch } = await client([[200, HELLO("e1")]]);
  const a = await c.send("box.steer", { id: "b1", text: "x".repeat(70 * 1024) });
  assert.equal(a.ok, false);
  assert.equal(a.error, "too_large");
  assert.equal(frames(fetch).length, 0);
});

test("send never rejects when signing fails", async () => {
  const dev = await newDevice();
  const { c, fetch } = await client([[200, HELLO("e1")]], { ...dev, key: {} });
  const a = await c.send("box.overview");
  assert.equal(a.ok, false);
  assert.equal(a.error, "invalid");
  assert.equal(typeof a.message, "string");
  assert.equal(frames(fetch).length, 0);
});
