import test from "node:test";
import assert from "node:assert/strict";
import { b64u } from "../js/wire.js";

class Node_ {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.className = ""; this.hidden = false; this.disabled = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { this.listeners[t] = f; }
  append(...k) { this.children.push(...k); }
  replaceChildren(...k) { this.children = k.map((x) => (typeof x === "string" ? { text: x } : x)); }
  focus() {}
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
globalThis.window = { confirm: () => true, addEventListener() {}, removeEventListener() {} };
const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

const SHA = "cd".repeat(32);
const CRED = new Uint8Array([1, 2, 3, 4]);
const buf = (a) => new Uint8Array(a).buffer;
const DIFF = { ok: true, result: { diff_sha256: SHA, base_commit: "0".repeat(40), files: [], unified: "", truncated: false, tests: null } };
const LAND = { request_id: "5", class: "land", box_id: "b-done", summary: "land b-done", challenge_hex: "ab".repeat(32), short_code: "123456", created_at: 1, expires_at: 9 };

function client(inbox) {
  const sent = [];
  return {
    sent,
    async send(action, args, opts = {}) {
      sent.push({ action, args, touch: opts.touch });
      if (action === "box.diff") return DIFF;
      if (action === "box.inbox") return { ok: true, result: { items: inbox } };
      if (action === "workspace.whoami") return { ok: true, result: { passkeys: [b64u(CRED)] } };
      if (action === "box.land") return { ok: true, result: {} };
      return { ok: false, error: "invalid", rule: "invalid", message: "unexpected" };
    },
  };
}

const credentials = {
  async get() {
    return { type: "public-key", rawId: buf(CRED), response: { authenticatorData: buf([1]), clientDataJSON: buf([2]), signature: buf([3]) } };
  },
};

async function approve(c) {
  const { view } = await import("../js/views/review.js");
  const root = view(c, "b-done", { credentials });
  await settle();
  const b = find(root, (n) => n.tag === "button" && texts(n).join("") === "Approve with touch");
  b.listeners.click();
  await settle();
  return root;
}

test("approve answers the pending land with one touched frame and no proof-less land", async () => {
  const c = client([LAND]);
  const root = await approve(c);
  const lands = c.sent.filter((x) => x.action === "box.land");
  assert.equal(lands.length, 1, JSON.stringify(c.sent));
  assert.deepEqual(lands[0].args, { id: "b-done", diff_sha256: SHA });
  assert.equal(lands[0].touch.request_id, "5");
  assert.equal(lands[0].touch.credential_id, b64u(CRED));
  assert.ok(texts(root).join("").includes("The machine accepted the request."));
});

test("approve without a pending land sends no land frame and shows the machine route", async () => {
  const c = client([]);
  const root = await approve(c);
  assert.equal(c.sent.filter((x) => x.action === "box.land").length, 0, JSON.stringify(c.sent));
  const all = texts(root).join("");
  assert.ok(all.includes("Not done yet"), all);
  assert.ok(all.includes("On the machine, run:"), all);
});
