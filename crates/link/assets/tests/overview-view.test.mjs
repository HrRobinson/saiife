import test from "node:test";
import assert from "node:assert/strict";

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.className = ""; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...k) { this.children.push(...k); }
  replaceChildren(...k) { this.children = k.filter((x) => x !== "").map((x) => (typeof x === "string" ? { text: x } : x)); }
}
const texts = (n) => (n.text !== undefined ? [n.text] : n.children.flatMap(texts));
function find(n, f) {
  if (f(n)) return n;
  for (const c of n.children || []) {
    const x = find(c, f);
    if (x) return x;
  }
  return null;
}
globalThis.document = {
  visibilityState: "visible",
  createElement: (t) => new Node_(t),
  createTextNode: (s) => ({ text: s }),
  addEventListener() {},
  removeEventListener() {},
};
const winListeners = {};
globalThis.window = {
  confirm: () => true,
  addEventListener: (t, f) => { winListeners[t] = f; },
  removeEventListener: () => {},
};

const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
};
const OV = (state) => ({ ok: true, result: { boxes: [{ id: "b-1", state, task: "t", template: "x", repo: "r", started_at: 1 }], slots_free: 1, load: null } });

// A client whose answers are released by hand, per call.
function heldClient() {
  const calls = [];
  return {
    calls,
    send(action, args) {
      return new Promise((resolve) => calls.push({ action, args, resolve }));
    },
  };
}

test("a lockdown result stays after polls, and a poll runs after it", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] });
  const { view } = await import("../js/views/overview.js");
  const client = heldClient();
  const root = view(client);
  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0].action, "box.overview");
  // A lockdown while the first poll is still in flight.
  const lock = find(root, (n) => n.tag === "button" && texts(n).join("") === "Lockdown on");
  lock.listeners.click();
  await settle();
  assert.equal(client.calls[1].action, "lockdown.on");
  client.calls[1].resolve({ ok: true, result: {} });
  await settle();
  assert.ok(texts(root).includes("Lockdown is on. Every agent is stopped."), texts(root).join("|"));
  // The old poll answers; then the action's refresh runs at once.
  client.calls[0].resolve(OV("running"));
  await settle();
  assert.equal(client.calls.length, 3, "a refresh after the action");
  assert.equal(client.calls[2].action, "box.overview");
  client.calls[2].resolve(OV("paused"));
  await settle();
  // A timer poll later: the action's result is still on the page.
  t.mock.timers.tick(3000);
  await settle();
  client.calls[3].resolve(OV("paused"));
  await settle();
  const all = texts(root);
  assert.ok(all.includes("Lockdown is on. Every agent is stopped."), all.join("|"));
  assert.ok(all.includes("paused"));
  winListeners.hashchange();
});

test("hostile state and id stay inert on a card", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] });
  const { view } = await import("../js/views/overview.js");
  const client = heldClient();
  const root = view(client);
  client.calls[0].resolve({
    ok: true,
    result: { boxes: [
      { id: "q‮1", state: "queued", task: "t", template: "x", repo: "r", started_at: 1 },
      { id: "d1", state: "done‮ x", task: "t", template: "x", repo: "r", started_at: 1 },
    ], slots_free: 0, load: null },
  });
  await settle();
  const badge = find(root, (n) => n.tag === "span" && (n.attrs.class || "").startsWith("badge") && texts(n).join("").startsWith("done"));
  assert.equal(badge.attrs.class, "badge state-other");
  assert.equal(texts(badge).join(""), "done⟨U+202E⟩ x");
  const up = find(root, (n) => (n.attrs?.["aria-label"] || "").startsWith("Move up"));
  assert.equal(up.attrs["aria-label"], "Move up q⟨U+202E⟩1");
  assert.ok(!texts(root).some((x) => x.startsWith("Running for")), "not for queued or unknown states");
  winListeners.hashchange();
});
