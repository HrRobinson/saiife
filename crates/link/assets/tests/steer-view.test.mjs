import test from "node:test";
import assert from "node:assert/strict";

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.className = ""; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...k) { this.children.push(...k); }
  replaceChildren(...k) { this.children = k.map((x) => (typeof x === "string" ? { text: x } : x)); }
  focus() {}
}
const texts = (n) => (n.text !== undefined ? [n.text] : n.children.flatMap(texts));
const tags = (n) => (n.tag === undefined ? [] : [n.tag, ...n.children.flatMap(tags)]);
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

test("the steer screen's terminal pane is text only and polls box.term.read", async (t) => {
  t.mock.timers.enable({ apis: ["setInterval", "Date"] });
  const { view } = await import("../js/views/steer.js");
  const sent = [];
  const client = {
    async send(action, args) {
      sent.push([action, args]);
      return {
        ok: true,
        result: {
          frames: [{ snapshot: { seq: 1, rows: 2, cols: 40, lines: ["\u001b]8;;https://x\u0007Approve", "ok"], cursor: [0, 0] } }],
          next: 1,
          ended: true,
        },
      };
    },
  };
  const root = view(client, "b-run");
  await settle();
  assert.deepEqual(sent, [["box.term.read", { id: "b-run" }]]);
  const pane = find(root, (n) => n.tag === "section" && n.attrs.class === "terminal");
  assert.ok(pane);
  const inPane = tags(pane);
  for (const bad of ["a", "button", "input", "textarea", "form", "select"]) assert.ok(!inPane.includes(bad), inPane.join());
  const all = texts(pane).join("");
  assert.ok(all.includes("⟨ESC⟩]8;;https://x⟨U+0007⟩Approve"), all);
  assert.ok(all.includes("The terminal has ended"), all);
  // Ended: no more reads, however long the page stays.
  t.mock.timers.tick(5000);
  await settle();
  assert.equal(sent.length, 1);
  winListeners.hashchange?.();
});
