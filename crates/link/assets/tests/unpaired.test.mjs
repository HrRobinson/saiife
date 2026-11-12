import test from "node:test";
import assert from "node:assert/strict";
import { memoryStore } from "../js/keystore.js";
import { leaveIfUnpaired, takeNotice, UNPAIRED, PAIR_AGAIN } from "../js/unpaired.js";

const device = () => ({
  key: {},
  publicRaw: new Uint8Array(65),
  deviceId: "d-0123456789abcdef",
  machineId: "0123456789abcdef0123456789abcdef",
});
const UNKNOWN = { ok: false, error: "unknown_device", rule: "unknown_device", message: "Unknown device" };

test("unknown device forgets the key and routes to the pair screen", async () => {
  const store = memoryStore();
  await store.saveDevice(device());
  const went = [];
  assert.equal(await leaveIfUnpaired(UNKNOWN, { store, go: (x) => went.push(x) }), true);
  assert.equal(await store.loadDevice(), null, "the key is forgotten");
  assert.deepEqual(went, ["#/pair"]);
  assert.equal(takeNotice(), true, "the pair screen says so");
  assert.equal(takeNotice(), false, "once");
  // No device in the store at all (the Client's own answer) is the same.
  const none = { ok: false, error: "unknown_device", rule: null, message: "x" };
  assert.equal(await leaveIfUnpaired(none, { store, go: (x) => went.push(x) }), true);
  takeNotice();
});

test("other answers are left to the screen", async () => {
  const store = memoryStore();
  await store.saveDevice(device());
  const went = [];
  for (const a of [
    { ok: true, result: {} },
    { ok: false, error: "touch_required", rule: "touch_required", message: "x" },
    { ok: false, error: "unreachable", rule: null, message: "x" },
    { ok: false, error: "forbidden", rule: "stale_epoch", message: "x" },
  ]) {
    assert.equal(await leaveIfUnpaired(a, { store, go: (x) => went.push(x) }), false);
  }
  assert.notEqual(await store.loadDevice(), null);
  assert.deepEqual(went, []);
  assert.equal(takeNotice(), false);
});

test("a store that cannot forget still routes", async () => {
  const store = { async forgetDevice() { throw new Error("no IndexedDB"); } };
  const went = [];
  assert.equal(await leaveIfUnpaired(UNKNOWN, { store, go: (x) => went.push(x) }), true);
  assert.deepEqual(went, ["#/pair"]);
  assert.equal(takeNotice(), true);
});

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...k) { this.children.push(...k); }
  replaceChildren(...k) { this.children = k; }
}
const texts = (n) => (n.text !== undefined ? [n.text] : n.children.flatMap(texts));

test("the pair screen says the browser is no longer paired and how to pair again", async () => {
  globalThis.document = { createElement: (t) => new Node_(t), createTextNode: (s) => ({ text: s }) };
  const { render } = await import("../js/views/pair.js");
  await leaveIfUnpaired(UNKNOWN, { store: memoryStore(), go: () => {} });
  const root = render({ name: "pair" });
  await new Promise((r) => setImmediate(r));
  const all = texts(root).join("|");
  assert.ok(all.includes(UNPAIRED), all);
  assert.ok(all.includes("saiife workspace pair --local"), all);
  assert.ok(!all.includes("This browser is paired"), all);
  assert.ok(PAIR_AGAIN.includes("saiife workspace pair --local"));
  // Without the notice, a plain visit shows the intro only.
  const plain = texts(render({ name: "pair" })).join("|");
  assert.ok(!plain.includes(UNPAIRED), plain);
});
